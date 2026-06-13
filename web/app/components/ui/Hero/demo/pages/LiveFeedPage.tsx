"use client";

import { useState } from "react";
import type { Action, LogEntry } from "../types";
import { Input, Btn } from "../components/ui";
import { LogTable } from "../components/LogTable";

export function LiveFeedPage({ logs, onExport }: { logs: LogEntry[]; onExport: () => void }) {
  const [filter, setFilter] = useState<Action | "all">("all");
  const [search, setSearch] = useState("");

  const filtered = logs.filter(l =>
    (filter === "all" || l.action === filter) &&
    (search === "" || l.ip.includes(search) || l.path.includes(search))
  );

  return (
    <div className="flex-1 overflow-y-auto p-3 sm:p-[14px_18px] flex flex-col gap-2.5">
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden flex flex-col" style={{ minHeight: 400 }}>
        <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800 flex-wrap gap-2">
          <div className="flex items-center gap-1.5">
            {(["all", "allow", "tarpit", "block"] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-2.5 py-0.5 rounded text-[10px] font-medium capitalize transition-colors cursor-pointer
                  ${filter === f ? "bg-zinc-700 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"}`}
              >
                {f}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <div className="w-48"><Input value={search} onChange={setSearch} placeholder="Filter by IP or path…" /></div>
            <Btn size="xs" onClick={onExport}>Export CSV</Btn>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto" style={{ maxHeight: 480 }}>
          <LogTable logs={filtered} maxHeight={9999} flash />
        </div>
        <div className="px-3 py-1.5 border-t border-zinc-800 text-[10px] text-zinc-500 flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
          Live — {filtered.length} of {logs.length} entries
        </div>
      </div>
    </div>
  );
}