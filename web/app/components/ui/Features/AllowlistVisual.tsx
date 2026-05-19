export default function AllowlistVisual({ animate }: { animate: boolean }) {
  const rows = [
    { type: "CIDR", value: "10.0.0.0/8",          allowed: true  },
    { type: "IP",   value: "203.0.113.5",          allowed: true  },
    { type: "UA",   value: "Googlebot/2.1",        allowed: true  },
    { type: "IP",   value: "185.220.101.5",        allowed: false },
    { type: "UA",   value: "python-requests/2.31", allowed: false },
  ];

  return (
    <div className="overflow-hidden rounded-xl border border-white/10 bg-zinc-950 text-xs">

      {/* Header row */}
      <div className="grid border-b border-white/10 px-4 py-3 text-[10px] uppercase tracking-wide text-zinc-500"
        style={{ gridTemplateColumns: "44px 1fr 20px" }}>
        <span>Type</span><span>Value</span><span />
      </div>

      {/* Data rows */}
      {rows.map((row, i) => (
        <div
          key={i}
          className={[
            "grid items-center gap-x-3 px-4 py-3 transition-[opacity,transform] duration-300",
            i < rows.length - 1 ? "border-b border-white/5" : "",
          ].join(" ")}
          style={{
            gridTemplateColumns: "44px 1fr 20px",
            opacity: animate ? 1 : 0,
            transform: animate ? "translateX(0)" : "translateX(-8px)",
            transitionDelay: `${i * 60}ms`,
          }}
        >
          <span className="rounded-full bg-white/5 px-2 py-0.5 text-[10px] uppercase tracking-wide text-zinc-500">
            {row.type}
          </span>
          <span className={`truncate ${row.allowed ? "text-zinc-200" : "text-zinc-500"}`}>
            {row.value}
          </span>
          {row.allowed ? (
            <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
              <circle cx="6.5" cy="6.5" r="6" fill="#22c55e" fillOpacity="0.15" stroke="#22c55e" strokeOpacity="0.35" strokeWidth="0.75" />
              <path d="M3.5 6.5L5.5 8.5L9.5 4.5" stroke="#22c55e" strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          ) : (
            <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
              <circle cx="6.5" cy="6.5" r="6" fill="#ef4444" fillOpacity="0.08" stroke="#ef4444" strokeOpacity="0.2" strokeWidth="0.75" />
              <path d="M4.5 4.5L8.5 8.5M8.5 4.5L4.5 8.5" stroke="#6b7280" strokeWidth="1.25" strokeLinecap="round" />
            </svg>
          )}
        </div>
      ))}
    </div>
  );
}