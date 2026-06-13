"use client";

import type { Page } from "../types";
import { NAV } from "../data";
import { COLOR } from "../theme";

// ─── Sidebar ───────────────────────────────────────────────────────────────────

export function Sidebar({ page, setPage, blockCount, proxyUp, latency }: {
  page: Page; setPage: (p: Page) => void; blockCount: number; proxyUp: boolean; latency: number;
}) {
  return (
    <div className="w-[196px] shrink-0 bg-zinc-900 border-r border-zinc-800 flex flex-col">
      <div className="flex items-center gap-2.5 px-3.5 pt-3.5 pb-3 border-b border-zinc-800">
        <div className="w-[26px] h-[26px] rounded-md bg-zinc-100 flex items-center justify-center shrink-0">
          <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="#09090b" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <polyline points="3,9 7,2 11,9" />
            <line x1={4.5} y1={6.5} x2={9.5} y2={6.5} />
            <line x1={7} y1={9} x2={7} y2={12} />
          </svg>
        </div>
        <div>
          <div className="text-[13px] font-medium text-zinc-100 tracking-tight">Thunderhead</div>
          <div className="text-[10px] text-zinc-500 mt-px">v0.4.1</div>
        </div>
      </div>

      <div className="flex-1 p-2 overflow-y-auto">
        {NAV.map(section => (
          <div key={section.section}>
            <div className="text-[10px] text-zinc-500 uppercase tracking-widest px-1.5 pt-2 pb-0.5">{section.section}</div>
            {section.items.map(item => (
              <button
                key={item.label}
                onClick={() => setPage(item.label as Page)}
                className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-md cursor-pointer text-xs transition-colors border-none bg-transparent
                  ${page === item.label ? "bg-zinc-800 text-zinc-100 font-medium" : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50"}`}
              >
                <i className={`ti ti-${item.icon} text-[15px] w-4 text-center shrink-0`} aria-hidden="true" />
                <span className="flex-1 text-left">{item.label}</span>
                {item.label === "Live feed" && blockCount > 0 && (
                  <span
                    className="text-[10px] rounded px-[5px] py-px"
                    style={{ background: COLOR.block.bg, color: COLOR.block.text, border: `0.5px solid ${COLOR.block.border}` }}
                  >
                    {blockCount}
                  </span>
                )}
              </button>
            ))}
          </div>
        ))}
      </div>

      <div className="p-2 border-t border-zinc-800">
        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-zinc-800 border border-zinc-700">
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${proxyUp ? "bg-green-500" : "bg-red-500"}`} />
          <span className="text-[11px] text-zinc-400">Proxy</span>
          <span className="text-[11px] font-medium ml-auto text-zinc-100 tabular-nums">
            {proxyUp ? `:8080 · ${latency}ms` : "offline"}
          </span>
        </div>
      </div>
    </div>
  );
}