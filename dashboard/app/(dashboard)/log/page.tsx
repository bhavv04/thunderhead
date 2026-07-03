"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../../lib/api";
import { usePoll } from "../../../lib/hooks";
import type { ClientsResponse } from "../../../lib/types";

interface LogEntry {
  id:     number;
  ip:     string;
  score:  number;
  action: "allow" | "tarpit" | "block";
  robots: boolean;
  ts:     number;
}

function scoreColor(score: number) {
  if (score >= 75) return "#f87171";
  if (score >= 40) return "#fbbf24";
  return "#4ade80";
}

export default function LogPage() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const prevRef = useRef<ClientsResponse | null>(null);
  const idRef   = useRef(0);
  const bottomRef = useRef<HTMLDivElement>(null);

  const fetchClients = useCallback(() => api.clients(), []);
  const { data } = usePoll(fetchClients, 3000);

  useEffect(() => {
    if (!data) return;
    const prev = prevRef.current;
    prevRef.current = data;
    if (!prev) return;

    const newEntries: LogEntry[] = [];
    for (const [ip, cs] of Object.entries(data.clients)) {
      const prevCs = prev.clients[ip];
      if (!prevCs || cs.request_count > prevCs.request_count) {
        const action: LogEntry["action"] =
          cs.score >= 75 ? "block" : cs.score >= 40 ? "tarpit" : "allow";
        newEntries.push({
          id:     ++idRef.current,
          ip,
          score:  cs.score,
          action,
          robots: cs.robots_violated,
          ts:     Date.now(),
        });
      }
    }
    if (newEntries.length > 0) {
      setEntries(prev => [...prev.slice(-499), ...newEntries]);
    }
  }, [data]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [entries]);

  return (
    <div className="flex-1 overflow-hidden flex flex-col p-4 gap-3">
      <div className="flex items-center justify-between">
        <h1 className="text-[13px] font-medium text-zinc-100">Request log</h1>
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
          <span className="text-[11px] text-zinc-500">{entries.length} entries</span>
        </div>
      </div>

      <div className="flex-1 bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden flex flex-col min-h-0">
        <div className="flex-1 overflow-y-auto min-h-0">
          {entries.length === 0 ? (
            <div className="flex items-center justify-center h-full text-[11px] text-zinc-500">
              Waiting for requests through the proxy...
            </div>
          ) : (
            <table className="w-full text-[11px] border-collapse">
              <thead className="sticky top-0">
                <tr>
                  {["Time", "IP", "Score", "Action", "Robots"].map(h => (
                    <th key={h} className="px-3 py-2 text-left text-[10px] font-medium text-zinc-500 uppercase tracking-wider border-b border-zinc-800 bg-zinc-900">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entries.map(e => {
                  const color = scoreColor(e.score);
                  return (
                    <tr key={e.id} className="border-b border-zinc-800/40 hover:bg-zinc-800/30 transition-colors">
                      <td className="px-3 py-1.5 tabular-nums text-zinc-500">
                        {new Date(e.ts).toTimeString().slice(0, 8)}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-zinc-300">{e.ip}</td>
                      <td className="px-3 py-1.5 tabular-nums font-medium" style={{ color }}>{e.score.toFixed(1)}</td>
                      <td className="px-3 py-1.5">
                        <span className="text-[10px] px-2 py-0.5 rounded-full font-medium"
                          style={{ color, background: `${color}18`, border: `0.5px solid ${color}40` }}>
                          {e.action}
                        </span>
                      </td>
                      <td className="px-3 py-1.5">
                        {e.robots ? <span className="text-yellow-400">yes</span> : <span className="text-zinc-600">no</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <div ref={bottomRef} />
        </div>
        <div className="px-3 py-1.5 border-t border-zinc-800 text-[10px] text-zinc-500 flex items-center gap-1.5 shrink-0">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
          Polling every 3s
        </div>
      </div>
    </div>
  );
}