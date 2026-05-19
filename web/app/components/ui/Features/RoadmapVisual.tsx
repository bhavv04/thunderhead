export default function RoadmapVisual({ animate }: { animate: boolean }) {
  const items = [
    { label: "Auto-fetch robots.txt",        done: true  },
    { label: "/thunderhead/status endpoint", done: true  },
    { label: "IP / CIDR / UA allowlist",     done: true  },
    { label: "Persistent score storage",     done: true  },
    { label: "CIDR range blocking",          done: true  },
    { label: "Dashboard UI",                 done: false },
    { label: "JS challenge mode",            done: false },
    { label: "Middleware (Go library)",      done: false },
  ];

  const done  = items.filter((i) => i.done).length;
  const total = items.length;
  const pct   = Math.round((done / total) * 100);

  return (
    <div className="flex flex-col gap-3">

      {/* Progress bar */}
      <div className="flex flex-col gap-2">
        <div className="flex justify-between text-xs text-zinc-500">
          <span>{done}/{total} complete</span>
          <span className="text-blue-500">{pct}%</span>
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-zinc-800">
          <div
            className="h-full rounded-full transition-[width] duration-700 ease-[cubic-bezier(0.16,1,0.3,1)] delay-200"
            style={{
              width: animate ? `${pct}%` : "0%",
              background: "linear-gradient(90deg, var(--accent), #60a5fa)",
            }}
          />
        </div>
      </div>

      {/* Items */}
      <div className="flex flex-col">
        {items.map((item, i) => (
          <div
            key={i}
            className={[
              "flex items-center gap-2.5 py-2 text-sm transition-opacity duration-300",
              i < items.length - 1 ? "border-b border-white/5" : "",
            ].join(" ")}
            style={{
              opacity: animate ? 1 : 0,
              transitionDelay: `${i * 45}ms`,
            }}
          >
            {item.done ? (
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="shrink-0">
                <circle cx="7" cy="7" r="6.25" fill="var(--green-dim)" stroke="rgba(34,197,94,0.3)" strokeWidth="0.75" />
                <path d="M4 7L6 9L10 5" stroke="#22c55e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="shrink-0">
                <circle cx="7" cy="7" r="6.25" fill="rgba(255,255,255,0.02)" stroke="rgba(255,255,255,0.1)" strokeWidth="0.75" strokeDasharray="3 2" />
              </svg>
            )}
            <span className={item.done ? "text-zinc-300" : "text-zinc-600"}>
              {item.label}
            </span>
          </div>
        ))}
      </div>

    </div>
  );
}