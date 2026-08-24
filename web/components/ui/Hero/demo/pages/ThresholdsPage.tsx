"use client";

import { useState } from "react";
import type { Action } from "@/components/ui/Hero/demo/types";
import { COLOR } from "@/components/ui/Hero/demo/theme";
import { Panel, Btn } from "@/components/ui/Hero/demo/components/ui";

export function ThresholdsPage({ thresholds, onChange }: {
  thresholds: { tarpit: number; block: number };
  onChange: (t: { tarpit: number; block: number }) => void;
}) {
  const [local, setLocal] = useState(thresholds);

  const apply = () => onChange(local);
  const reset = () => { setLocal({ tarpit: 40, block: 75 }); onChange({ tarpit: 40, block: 75 }); };

  const tarpitPct = (local.tarpit / 100) * 100;
  const blockPct  = (local.block  / 100) * 100;
  const allowW    = local.tarpit;
  const tarpitW   = local.block - local.tarpit;
  const blockW    = 100 - local.block;

  return (
    <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-3">
      <Panel title="Intent score thresholds" right="drag to adjust">
        <div className="flex flex-col gap-5">
          {/* Visual band */}
          <div className="relative">
            <div className="flex h-3 rounded overflow-hidden gap-0.5">
              <div style={{ flex: allowW,  background: COLOR.allow.bg,  border: `1px solid ${COLOR.allow.border}` }} className="rounded-l" />
              <div style={{ flex: tarpitW, background: COLOR.tarpit.bg, border: `1px solid ${COLOR.tarpit.border}` }} />
              <div style={{ flex: blockW,  background: COLOR.block.bg,  border: `1px solid ${COLOR.block.border}` }} className="rounded-r" />
            </div>
            <div className="flex justify-between text-[10px] text-zinc-500 mt-1">
              <span>0</span>
              <span style={{ marginLeft: `${tarpitPct - 3}%` }}>{local.tarpit} tarpit</span>
              <span style={{ marginLeft: `${blockPct - tarpitPct - 5}%` }}>{local.block} block</span>
              <span>100</span>
            </div>
          </div>

          {/* Tarpit slider */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <label className="text-[11px] font-medium text-zinc-300">Tarpit threshold</label>
              <span className="text-[11px] font-medium tabular-nums" style={{ color: COLOR.tarpit.text }}>{local.tarpit}</span>
            </div>
            <input
              type="range" min={1} max={local.block - 1} value={local.tarpit}
              onChange={e => setLocal(p => ({ ...p, tarpit: +e.target.value }))}
              className="w-full accent-yellow-400 cursor-pointer"
            />
            <p className="text-[10px] text-zinc-500">Requests with a score at or above this value are delayed by 5 seconds before responding.</p>
          </div>

          {/* Block slider */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <label className="text-[11px] font-medium text-zinc-300">Block threshold</label>
              <span className="text-[11px] font-medium tabular-nums" style={{ color: COLOR.block.text }}>{local.block}</span>
            </div>
            <input
              type="range" min={local.tarpit + 1} max={99} value={local.block}
              onChange={e => setLocal(p => ({ ...p, block: +e.target.value }))}
              className="w-full accent-red-400 cursor-pointer"
            />
            <p className="text-[10px] text-zinc-500">Requests with a score at or above this value are blocked with a 403 response.</p>
          </div>

          <div className="flex gap-2 pt-1">
            <Btn onClick={apply}>Apply</Btn>
            <Btn variant="ghost" onClick={reset}>Reset to defaults</Btn>
          </div>
        </div>
      </Panel>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
        {([
          { a: "allow"  as Action, label: "Allow zone",  range: `0 – ${local.tarpit - 1}`,      desc: "Pass through immediately." },
          { a: "tarpit" as Action, label: "Tarpit zone", range: `${local.tarpit} – ${local.block - 1}`, desc: "Introduce a 5s artificial delay." },
          { a: "block"  as Action, label: "Block zone",  range: `${local.block} – 100`,          desc: "Return 403 Forbidden." },
        ]).map(z => (
          <div key={z.a} className="bg-zinc-900 border border-zinc-800 rounded-lg p-3.5 flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: COLOR[z.a].text }} />
              <span className="text-[11px] font-medium text-zinc-100">{z.label}</span>
            </div>
            <span className="text-[13px] font-semibold tabular-nums" style={{ color: COLOR[z.a].text }}>{z.range}</span>
            <span className="text-[10px] text-zinc-500">{z.desc}</span>
          </div>
        ))}
      </div>
    </div>
  );
}