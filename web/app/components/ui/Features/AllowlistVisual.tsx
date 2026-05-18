export default function AllowlistVisual({ animate }: { animate: boolean }) {
  const rows = [
    { type: "CIDR", value: "10.0.0.0/8",          allowed: true  },
    { type: "IP",   value: "203.0.113.5",          allowed: true  },
    { type: "UA",   value: "Googlebot/2.1",        allowed: true  },
    { type: "IP",   value: "185.220.101.5",        allowed: false },
    { type: "UA",   value: "python-requests/2.31", allowed: false },
  ];

  return (
    <div style={{
      background: "var(--gray-950)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      overflow: "hidden",
      fontFamily: "var(--font-mono)",
      fontSize: 11,
    }}>
      <div style={{
        display: "grid",
        gridTemplateColumns: "44px 1fr 20px",
        gap: "0 12px",
        padding: "7px 14px",
        borderBottom: "1px solid var(--border)",
        color: "var(--gray-700)",
        fontSize: 9,
        letterSpacing: "0.1em",
        textTransform: "uppercase" as const,
      }}>
        <span>Type</span><span>Value</span><span />
      </div>
      {rows.map((row, i) => (
        <div key={i} style={{
          display: "grid",
          gridTemplateColumns: "44px 1fr 20px",
          gap: "0 12px",
          padding: "7px 14px",
          borderBottom: i < rows.length - 1 ? "1px solid rgba(255,255,255,0.03)" : "none",
          alignItems: "center",
          opacity: animate ? 1 : 0,
          transform: animate ? "translateX(0)" : "translateX(-8px)",
          transition: `opacity 350ms ease ${i * 60}ms, transform 350ms ease ${i * 60}ms`,
        }}>
          <span style={{
            color: "var(--gray-700)",
            fontSize: 9,
            letterSpacing: "0.06em",
            textTransform: "uppercase" as const,
            background: "rgba(255,255,255,0.04)",
            borderRadius: 3,
            padding: "1px 5px",
          }}>
            {row.type}
          </span>
          <span style={{
            color: row.allowed ? "var(--gray-300)" : "var(--gray-700)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap" as const,
          }}>
            {row.value}
          </span>
          {row.allowed ? (
            <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
              <circle cx="6.5" cy="6.5" r="6" fill="#22c55e" fillOpacity="0.15" stroke="#22c55e" strokeOpacity="0.4" strokeWidth="0.75" />
              <path d="M3.5 6.5L5.5 8.5L9.5 4.5" stroke="#22c55e" strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          ) : (
            <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
              <circle cx="6.5" cy="6.5" r="6" fill="#ef4444" fillOpacity="0.08" stroke="#ef4444" strokeOpacity="0.2" strokeWidth="0.75" />
              <path d="M4.5 4.5L8.5 8.5M8.5 4.5L4.5 8.5" stroke="#3f3f46" strokeWidth="1.25" strokeLinecap="round" />
            </svg>
          )}
        </div>
      ))}
    </div>
  );
}