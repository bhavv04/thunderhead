"use client";

import { useState } from "react";
import { Panel, Input, Btn } from "@/components/ui/Hero/demo/components/ui";

export function AllowlistPage() {
  const [entries, setEntries] = useState<string[]>(["66.249.64.0/24", "54.92.0.0/16", "172.16.0.0/12"]);
  const [input, setInput] = useState("");
  const [error, setError] = useState("");

  const add = () => {
    const v = input.trim();
    if (!v) return;
    if (entries.includes(v)) { setError("Already in allowlist."); return; }
    setEntries(p => [...p, v]);
    setInput("");
    setError("");
  };

  return (
    <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-3">
      <Panel title="IP / CIDR allowlist" right={`${entries.length} entries`}>
        <div className="flex flex-col gap-3">
          <div className="flex gap-2">
            <Input value={input} onChange={v => { setInput(v); setError(""); }} placeholder="e.g. 1.2.3.4 or 10.0.0.0/8" />
            <Btn onClick={add}>Add</Btn>
          </div>
          {error && <p className="text-[10px] text-red-400">{error}</p>}
          <div className="flex flex-col divide-y divide-zinc-800">
            {entries.length === 0 && <div className="text-[11px] text-zinc-500 py-2">No entries. Add an IP or CIDR range above.</div>}
            {entries.map(e => (
              <div key={e} className="flex items-center justify-between py-2">
                <span className="text-[12px] text-zinc-200 font-mono">{e}</span>
                <Btn size="xs" variant="danger" onClick={() => setEntries(p => p.filter(x => x !== e))}>Remove</Btn>
              </div>
            ))}
          </div>
        </div>
      </Panel>
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3.5 text-[11px] text-zinc-400 leading-relaxed">
        Allowlisted IPs bypass all scoring and are always passed through. CIDR notation is supported (e.g. <code className="text-zinc-300 font-mono">10.0.0.0/8</code>). Changes take effect immediately.
      </div>
    </div>
  );
}