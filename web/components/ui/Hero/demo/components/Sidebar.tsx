"use client";

import { useState, useEffect } from "react";
import type { Page } from "@/components/ui/Hero/demo/types";
import { NAV } from "@/components/ui/Hero/demo/data";
import { COLOR } from "@/components/ui/Hero/demo/theme";
import {
  LayoutDashboard, Rss, BarChart3, SlidersHorizontal,
  ShieldCheck, Radio, ScrollText, Settings,
} from "lucide-react";
import Image from "next/image";

const NAV_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  "Overview": LayoutDashboard,
  "Live feed": Rss,
  "Analytics": BarChart3,
  "Thresholds": SlidersHorizontal,
  "Allowlist": ShieldCheck,
  "Signals": Radio,
  "Logs": ScrollText,
  "Settings": Settings,
};

// ─── Sidebar ───────────────────────────────────────────────────────────────

export function Sidebar({ page, setPage, blockCount, proxyUp, latency }: {
  page: Page; setPage: (p: Page) => void; blockCount: number; proxyUp: boolean; latency: number;
}) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  return (
    <div className="w-48 shrink-0 bg-sidebar-bg flex flex-col">
      <div className="flex items-center gap-2 p-4 pb-3">
            <Image src="/favicon-192.png" alt="Logo" width={28} height={28} className="rounded-md" />
        <div>
          <div className="text-sm font-medium text-zinc-100 tracking-tight">Thunderhead</div>
          <div className="text-xs text-zinc-500">v0.4.1</div>
        </div>
      </div>

      <div className="flex-1 p-2 overflow-y-auto">
        {NAV.map(section => (
          <div key={section.section}>
            <div className="text-xs text-zinc-500 px-2 pt-2 pb-1">{section.section}</div>
            {section.items.map(item => {
              const Icon = NAV_ICON[item.label] ?? LayoutDashboard;
              return (
                <button
                  key={item.label}
                  onClick={() => setPage(item.label as Page)}
                  className={`w-full flex items-center gap-2 px-2 py-2 rounded-md cursor-pointer text-xs transition-colors border-none bg-transparent
                    ${page === item.label ? "bg-zinc-800 text-zinc-100 font-medium" : "text-zinc-400 hover:text-white"}`}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span className="flex-1 text-left">{item.label}</span>
                  {item.label === "Live feed" && mounted && blockCount > 0 && (
                    <span
                      className="text-xxs"
                      style={{ background: COLOR.block.bg, color: COLOR.block.text, border: `1px solid ${COLOR.block.border}` }}
                    >
                      {blockCount}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </div>

      <div className="p-2">
        <div className="flex items-center gap-2 px-3 py-2">
          <span className="text-xs text-zinc-400">Proxy</span>
          <span className="text-xs font-medium ml-auto text-zinc-100 tabular-nums">
            {proxyUp ? "thunderhead.app" : "offline"}
          </span>
        </div>
      </div>
    </div>
  );
}