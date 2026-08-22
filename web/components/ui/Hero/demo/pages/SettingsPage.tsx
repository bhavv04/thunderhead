"use client";

import { useState } from "react";
import { Panel, Btn } from "@/components/ui/Hero/demo/components/ui";

export function SettingsPage({ proxyUp, onToggleProxy }: { proxyUp: boolean; onToggleProxy: () => void }) {
  const [port, setPort] = useState("8080");
  const [retention, setRetention] = useState("500");
  const [saved, setSaved] = useState(false);

  const save = () => { setSaved(true); setTimeout(() => setSaved(false), 2000); };

  return (
    <div className="flex-1 overflow-y-auto p-3 sm:p-[14px_18px] flex flex-col gap-2.5">
      <Panel title="Proxy settings">
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label className="text-[11px] font-medium text-zinc-300">Listen port</label>
            <input
              value={port} onChange={e => setPort(e.target.value)}
              className="bg-zinc-800 border border-zinc-700 rounded-md px-3 py-1.5 text-[12px] text-zinc-200 font-mono focus:outline-none focus:border-zinc-500 w-32"
            />
            <p className="text-[10px] text-zinc-500">The port Thunderhead listens on for incoming traffic.</p>
          </div>
          <div className="flex flex-col gap-1.5">
            <label className="text-[11px] font-medium text-zinc-300">Log retention (entries)</label>
            <input
              value={retention} onChange={e => setRetention(e.target.value)}
              className="bg-zinc-800 border border-zinc-700 rounded-md px-3 py-1.5 text-[12px] text-zinc-200 font-mono focus:outline-none focus:border-zinc-500 w-32"
            />
            <p className="text-[10px] text-zinc-500">Maximum number of log entries kept in memory.</p>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-[11px] font-medium text-zinc-300">Proxy status</div>
              <div className="text-[10px] text-zinc-500 mt-0.5">Start or stop the intercept proxy.</div>
            </div>
            <button
              onClick={onToggleProxy}
              className={`px-3 py-1.5 rounded text-xs cursor-pointer transition-all duration-200 ease-in-out
                ${proxyUp
                  ? "bg-stone-800 text-zinc-400 hover:bg-stone-700"
                  : "bg-stone-800 text-zinc-400 hover:bg-stone-700"
                }`}
            >
              {proxyUp ? "Stop proxy" : "Start proxy"}
            </button>
          </div>
          <div className="flex gap-2 pt-1 border-t border-zinc-800">
            <Btn onClick={save}>{saved ? "✓ Saved" : "Save changes"}</Btn>
            <Btn variant="ghost">Cancel</Btn>
          </div>
        </div>
      </Panel>

      <Panel title="Danger zone">
        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-[11px] font-medium text-zinc-300">Reset all settings</div>
              <div className="text-[10px] text-zinc-500 mt-0.5">Restore thresholds, signals, and allowlist to defaults.</div>
            </div>
            <Btn variant="danger">Reset</Btn>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-[11px] font-medium text-zinc-300">Flush log buffer</div>
              <div className="text-[10px] text-zinc-500 mt-0.5">Clear all in-memory log entries immediately.</div>
            </div>
            <Btn variant="danger">Flush</Btn>
          </div>
        </div>
      </Panel>
    </div>
  );
}