"use client";

import { useState } from "react";
import type { Action, LogEntry } from "@/components/ui/Hero/demo/types";
import { Input, Btn } from "@/components/ui/Hero/demo/components/ui";
import { LogTable } from "@/components/ui/Hero/demo/components/LogTable";

export function LogsPage({ logs, onExport }: { logs: LogEntry[]; onExport: () => void }) {
  const [frozen] = useState([...logs]);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Action | "all">("all");

  const filtered = frozen.filter(l =>
    (filter === "all" || l.action === filter) &&
    (search === "" || l.ip.includes(search) || l.path.includes(search))
  );

  return (
    <div className="flex-1 overflow-y-auto p-2 flex flex-col">
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden flex flex-col min-h-0">
        <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800 flex-wrap gap-2 shrink-0">
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
            <div className="w-40"><Input value={search} onChange={setSearch} placeholder="Search…" /></div>
            <Btn size="xs" onClick={onExport}>Export CSV</Btn>
          </div>
        </div>
        <LogTable logs={filtered} maxHeight={500} />
        <div className="px-3 py-1.5 border-t border-zinc-800 text-xs text-zinc-500">
          Snapshot from session start — {filtered.length} of {frozen.length} entries
        </div>
      </div>
    </div>
  );
}