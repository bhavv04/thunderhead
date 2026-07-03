"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import Link from "next/link";

const NAV = [
  { label: "Overview",   href: "/overview",   icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" },
  { label: "Clients",    href: "/clients",    icon: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0" },
  { label: "Log",        href: "/log",        icon: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" },
  { label: "Blocklist",  href: "/blocklist",  icon: "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" },
  { label: "Allowlist",  href: "/allowlist",  icon: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0" },
  { label: "Config",     href: "/config",     icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0" },
] as const;

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router   = useRouter();
  const [url, setUrl] = useState("");

  useEffect(() => {
    const saved = localStorage.getItem("th_url");
    if (!saved) { router.replace("/"); return; }
    setUrl(saved);
  }, [router]);

  function handleDisconnect() {
    localStorage.removeItem("th_url");
    localStorage.removeItem("th_key");
    router.replace("/");
  }

  return (
    <div className="flex h-screen bg-zinc-950 overflow-hidden">
      {/* Sidebar */}
      <div className="w-[200px] shrink-0 bg-zinc-900 border-r border-zinc-800 flex flex-col">
        <div className="flex items-center gap-2.5 px-3.5 pt-3.5 pb-3 border-b border-zinc-800">
          <div className="w-[26px] h-[26px] rounded-md bg-white flex items-center justify-center shrink-0">
            <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="#09090b" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <polyline points="3,9 7,2 11,9" />
              <line x1={4.5} y1={6.5} x2={9.5} y2={6.5} />
              <line x1={7} y1={9} x2={7} y2={12} />
            </svg>
          </div>
          <div>
            <div className="text-[13px] font-medium text-zinc-100 tracking-tight">Thunderhead</div>
            <div className="text-[10px] text-zinc-500 mt-px">v0.2.0</div>
          </div>
        </div>

        <nav className="flex-1 p-2 overflow-y-auto">
          {NAV.map(item => {
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-2 px-2 py-1.5 rounded-md text-xs transition-colors mb-0.5
                  ${active
                    ? "bg-zinc-800 text-zinc-100 font-medium"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50"
                  }`}
              >
                <svg className="w-4 h-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" viewBox="0 0 24 24">
                  <path d={item.icon} />
                </svg>
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="p-2 border-t border-zinc-800">
          <div className="px-2 py-1.5 rounded-md bg-zinc-800 border border-zinc-700 mb-1.5">
            <div className="text-[10px] text-zinc-500 mb-0.5">Connected to</div>
            <div className="text-[11px] text-zinc-300 truncate">{url}</div>
          </div>
          <button
            onClick={handleDisconnect}
            className="w-full text-[11px] text-zinc-500 hover:text-zinc-300 py-1 transition-colors"
          >
            Disconnect
          </button>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        {children}
      </div>
    </div>
  );
}