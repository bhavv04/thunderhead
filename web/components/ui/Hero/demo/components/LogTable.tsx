"use client";

import { useEffect, useRef, useState } from "react";
import type { LogEntry } from "@/components/ui/Hero/demo/types";
import { ActionBadge, ScoreChip } from "@/components/ui/Hero/demo/components/ui";

export function LogTable({ logs, showTime = true, maxHeight = 186, flash = false }: {
  logs: LogEntry[]; showTime?: boolean; maxHeight?: number; flash?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [logs]);

  if (logs.length === 0) return <div className="px-3 py-4 text-zinc-500">No entries.</div>;

  return (
    <div ref={ref} style={{ maxHeight }} className="overflow-y-auto">
      <table className="w-full border-collapse text-xs">
        <thead>
          <tr>
            {showTime && (
              <th className="hidden sm:table-cell px-2.5 py-1.5 text-left text-[10px] font-medium text-zinc-500 bg-zinc-800 uppercase tracking-wider sticky top-0 z-10 border-b border-zinc-700">
                Time
              </th>
            )}
            <th className="px-2.5 py-1.5 text-left text-[10px] font-medium text-zinc-500 bg-zinc-800 uppercase tracking-wider sticky top-0 z-10 border-b border-zinc-700">
              IP address
            </th>
            <th className="px-2.5 py-1.5 text-left text-[10px] font-medium text-zinc-500 bg-zinc-800 uppercase tracking-wider sticky top-0 z-10 border-b border-zinc-700">
              Path
            </th>
            <th className="hidden sm:table-cell px-2.5 py-1.5 text-left text-[10px] font-medium text-zinc-500 bg-zinc-800 uppercase tracking-wider sticky top-0 z-10 border-b border-zinc-700">
              Score
            </th>
            <th className="px-2.5 py-1.5 text-left text-[10px] font-medium text-zinc-500 bg-zinc-800 uppercase tracking-wider sticky top-0 z-10 border-b border-zinc-700">
              Action
            </th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, idx) => (
            <tr
              key={log.id}
              className={`border-b border-zinc-800/60 transition-colors ${mounted && flash && idx === logs.length - 1 ? "" : ""}`}
            >
              {showTime && <td className="hidden sm:table-cell px-2.5 py-[5px] text-zinc-500 whitespace-nowrap tabular-nums">{log.time}</td>}
              <td className="px-2.5 py-[5px] text-zinc-400 whitespace-nowrap tabular-nums">{log.ip}</td>
              <td className="px-2.5 py-[5px] text-zinc-100 whitespace-nowrap">{log.path}</td>
              <td className="hidden sm:table-cell px-2.5 py-[5px]"><ScoreChip score={log.score} action={log.action} /></td>
              <td className="px-2.5 py-[5px]"><ActionBadge action={log.action} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}