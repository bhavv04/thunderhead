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
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--gray-600)" }}>
          <span>{done}/{total} complete</span>
          <span style={{ color: "var(--accent)" }}>{pct}%</span>
        </div>
        <div style={{ height: 5, background: "var(--gray-800)", borderRadius: 99, overflow: "hidden" }}>
          <div style={{
            height: "100%",
            width: animate ? `${pct}%` : "0%",
            background: "linear-gradient(90deg, var(--accent), #60a5fa)",
            borderRadius: 99,
            transition: "width 900ms cubic-bezier(0.16,1,0.3,1) 200ms",
          }} />
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
        {items.map((item, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: 10,
            paddingBlock: 6,
            borderBottom: i < items.length - 1 ? "1px solid rgba(255,255,255,0.03)" : "none",
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            opacity: animate ? 1 : 0,
            transition: `opacity 280ms ease ${i * 45}ms`,
          }}>
            {item.done ? (
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <circle cx="7" cy="7" r="6.25" fill="var(--green-dim)" stroke="rgba(34,197,94,0.3)" strokeWidth="0.75" />
                <path d="M4 7L6 9L10 5" stroke="#22c55e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <circle cx="7" cy="7" r="6.25" fill="rgba(255,255,255,0.02)" stroke="rgba(255,255,255,0.1)" strokeWidth="0.75" strokeDasharray="3 2" />
              </svg>
            )}
            <span style={{ color: item.done ? "var(--gray-300)" : "var(--gray-700)" }}>
              {item.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}