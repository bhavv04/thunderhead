"use client";

import type { Page } from "@/components/ui/Hero/demo/types";

// ─── Bottom nav (mobile) ───────────────────────────────────────────────────────

export function BottomNav({ page, setPage, blockCount }: {
  page: Page; setPage: (p: Page) => void; blockCount: number;
}) {
  const items: { label: Page; icon: string; badge?: number }[] = [
    { label: "Overview", icon: "layout-dashboard" },
    { label: "Live feed", icon: "activity", badge: blockCount > 0 ? blockCount : undefined },
    { label: "Analytics", icon: "chart-line" },
    { label: "Settings", icon: "settings" },
  ];

  return (
    <div className="flex bg-zinc-900 border-t border-zinc-800 shrink-0">
      {items.map(item => (
        <button
          key={item.label}
          onClick={() => setPage(item.label)}
          className="flex-1 flex flex-col items-center gap-0.5 py-1.5 cursor-pointer relative bg-transparent border-none"
        >
          <div className="relative">
            <i className={`ti ti-${item.icon} text-xl ${page === item.label ? "text-zinc-100" : "text-zinc-500"}`} aria-hidden="true" />
            {item.badge && (
              <span className="absolute -top-1 -right-1.5 text-[9px] bg-red-400 text-white rounded-full px-1 font-semibold leading-[1.4]">
                {item.badge}
              </span>
            )}
          </div>
          <span className={`text-[10px] ${page === item.label ? "text-zinc-100" : "text-zinc-500"}`}>{item.label}</span>
        </button>
      ))}
    </div>
  );
}