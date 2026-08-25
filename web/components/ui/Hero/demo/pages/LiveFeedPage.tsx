"use client";

import { useState } from "react";
import type { Action, LogEntry } from "@/components/ui/Hero/demo/types";
import { Input, Btn } from "@/components/ui/Hero/demo/components/ui";
import { LogTable } from "@/components/ui/Hero/demo/components/LogTable";

export function LiveFeedPage({ logs, onExport }: { logs: LogEntry[]; onExport: () => void }) {
  const [filter, setFilter] = useState<Action | "all">("all");
  const [search, setSearch] = useState("");

  const filtered = logs.filter(l =>
    (filter === "all" || l.action === filter) &&
    (search === "" || l.ip.includes(search) || l.path.includes(search))
  );

  return (
<div className="flex-1 overflow-hidden p-2 flex flex-col min-h-0">
    <div className="rounded-lg overflow-hidden flex flex-col flex-1 min-h-0">
      <div className="flex items-center justify-between px-3 py-2 flex-wrap gap-2 shrink-0">
          <div className="flex items-center gap-2">   
            {(["all", "allow", "tarpit", "block"] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1 rounded text-xs transition-colors cursor-pointer
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
      <div className="flex-1 overflow-y-auto min-h-0">
          <LogTable logs={filtered} maxHeight={9999} flash/>
        </div>
      <div className="px-3 py-1.5 border-t border-zinc-800 text-xs text-zinc-500 flex items-center gap-1.5 shrink-0">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
          Live - {filtered.length} of {logs.length} entries since last view
        </div>
      </div>
    </div>
  );
}