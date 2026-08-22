"use client";

import { useCallback, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";

function scoreColor(score: number) {
  if (score >= 75) return "#f87171";
  if (score >= 40) return "#fbbf24";
  return "#4ade80";
}

export default function ClientsPage() {
  const [blocking, setBlocking] = useState<string | null>(null);
  const [blocked,  setBlocked]  = useState<Set<string>>(new Set());

  const fetchClients = useCallback(() => api.clients(), []);
  const { data, error, loading, refetch } = usePoll(fetchClients, 5000);

  async function handleBlock(ip: string) {
    setBlocking(ip);
    try {
      await api.blocklistAdd(ip);
      setBlocked(prev => new Set([...prev, ip]));
    } catch (e) {
      console.error(e);
    } finally {
      setBlocking(null);
    }
  }

  if (loading) return <div className="flex-1 flex items-center justify-center text-zinc-500 text-sm">Loading...</div>;
  if (error)   return <div className="flex-1 flex items-center justify-center text-red-400 text-sm">{error}</div>;

  const clientList = Object.entries(data!.clients).sort((a, b) => b[1].score - a[1].score);

  return (
    <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h1 className="text-[13px] font-medium text-zinc-100">Clients</h1>
        <span className="text-[11px] text-zinc-500">{clientList.length} tracked</span>
      </div>

      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
        {clientList.length === 0 ? (
          <div className="px-3 py-8 text-[11px] text-zinc-500 text-center">
            No clients tracked yet.
          </div>
        ) : (
          <table className="w-full text-[11px] border-collapse">
            <thead>
              <tr>
                {["IP", "Score", "Requests", "Robots", "Action", ""].map(h => (
                  <th key={h} className="px-3 py-2 text-left text-[10px] font-medium text-zinc-500 uppercase tracking-wider border-b border-zinc-800">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {clientList.map(([ip, cs]) => {
                const action  = cs.score >= 75 ? "block" : cs.score >= 40 ? "tarpit" : "allow";
                const color   = scoreColor(cs.score);
                const isBlocked = blocked.has(ip);
                return (
                  <tr key={ip} className="border-b border-zinc-800/60 hover:bg-zinc-800/30 transition-colors">
                    <td className="px-3 py-2 font-mono text-zinc-300">{ip}</td>
                    <td className="px-3 py-2 tabular-nums font-medium" style={{ color }}>{cs.score.toFixed(1)}</td>
                    <td className="px-3 py-2 tabular-nums text-zinc-400">{cs.request_count}</td>
                    <td className="px-3 py-2">{cs.robots_violated ? <span className="text-yellow-400">yes</span> : <span className="text-zinc-500">no</span>}</td>
                    <td className="px-3 py-2">
                      <span className="text-[10px] px-2 py-0.5 rounded-full font-medium"
                        style={{ color, background: `${color}18`, border: `0.5px solid ${color}40` }}>
                        {action}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      {isBlocked ? (
                        <span className="text-[10px] text-zinc-500">blocked</span>
                      ) : (
                        <button
                          onClick={() => handleBlock(ip)}
                          disabled={blocking === ip}
                          className="text-[10px] px-2 py-0.5 rounded border border-zinc-700 text-zinc-400 hover:text-red-400 hover:border-red-800 transition-colors disabled:opacity-40"
                        >
                          {blocking === ip ? "..." : "block"}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}