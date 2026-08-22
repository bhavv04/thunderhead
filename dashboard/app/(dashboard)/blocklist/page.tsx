"use client";

import { useCallback, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";

export default function BlocklistPage() {
  const [input,   setInput]   = useState("");
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");

  const fetch = useCallback(() => api.blocklist(), []);
  const { data, refetch } = usePoll(fetch, 10000);

  async function handleAdd() {
    if (!input.trim()) return;
    setLoading(true); setError("");
    try {
      await api.blocklistAdd(input.trim());
      setInput("");
      refetch();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleRemove(entry: string) {
    try {
      await api.blocklistRemove(entry);
      refetch();
    } catch (e) {
      console.error(e);
    }
  }

  const ips   = data?.ips   ?? [];
  const cidrs = data?.cidrs ?? [];
  const all   = [...ips, ...cidrs];

  return (
    <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
      <h1 className="text-[13px] font-medium text-zinc-100">Blocklist</h1>

      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 flex flex-col gap-3">
        <div className="text-[11px] font-medium text-zinc-300">Add entry</div>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleAdd()}
            placeholder="IP address or CIDR (e.g. 1.2.3.4 or 10.0.0.0/8)"
            className="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-[12px] text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
          />
          <button
            onClick={handleAdd}
            disabled={loading || !input.trim()}
            className="px-4 py-2 bg-zinc-100 text-zinc-950 rounded-lg text-[12px] font-medium hover:bg-white transition-colors disabled:opacity-40"
          >
            {loading ? "..." : "Add"}
          </button>
        </div>
        {error && <div className="text-[11px] text-red-400">{error}</div>}
      </div>

      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
        <div className="px-3 py-2 border-b border-zinc-800 text-[11px] font-medium text-zinc-100">
          {all.length} entries
        </div>
        {all.length === 0 ? (
          <div className="px-3 py-6 text-[11px] text-zinc-500 text-center">No entries yet.</div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {all.map(entry => (
              <div key={entry} className="flex items-center justify-between px-3 py-2">
                <span className="font-mono text-[12px] text-zinc-300">{entry}</span>
                <button
                  onClick={() => handleRemove(entry)}
                  className="text-[11px] text-zinc-500 hover:text-red-400 transition-colors"
                >
                  remove
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}