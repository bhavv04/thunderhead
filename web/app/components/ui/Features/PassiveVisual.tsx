export default function PassiveVisual({ animate }: { animate: boolean }) {
  const signals = [
    { icon: "📄", label: "robots.txt check",       status: "passive" },
    { icon: "📍", label: "Path sequence tracking", status: "passive" },
    { icon: "⏱",  label: "Rate window (60s)",      status: "passive" },
    { icon: "🔍", label: "Header inspection",       status: "passive" },
    { icon: "📝", label: "Content-type analysis",  status: "passive" },
  ];

  const blocked = [
    { label: "JS challenge" },
    { label: "CAPTCHA"      },
    { label: "Cookies set"  },
    { label: "Fingerprint"  },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{
        background: "var(--gray-950)",
        border: "1px solid var(--border)",
        borderRadius: 10,
        overflow: "hidden",
        fontFamily: "var(--font-mono)",
        fontSize: 11,
      }}>
        <div style={{ padding: "6px 12px", borderBottom: "1px solid var(--border)", fontSize: 9, color: "var(--gray-600)", letterSpacing: "0.08em" }}>
          PASSIVE SIGNALS ONLY
        </div>
        {signals.map((s, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: 10,
            padding: "6px 12px",
            borderBottom: i < signals.length - 1 ? "1px solid rgba(255,255,255,0.03)" : "none",
            opacity: animate ? 1 : 0,
            transition: `opacity 300ms ease ${i * 50}ms`,
          }}>
            <span style={{ fontSize: 12 }}>{s.icon}</span>
            <span style={{ color: "var(--gray-400)", flex: 1 }}>{s.label}</span>
            <span style={{
              fontSize: 9, letterSpacing: "0.06em",
              background: "var(--green-dim)",
              color: "var(--green)",
              border: "1px solid rgba(34,197,94,0.2)",
              borderRadius: 4,
              padding: "1px 6px",
            }}>
              {s.status}
            </span>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
        {blocked.map((b, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: 6,
            padding: "6px 10px",
            borderRadius: 7,
            background: "rgba(239,68,68,0.04)",
            border: "1px solid rgba(239,68,68,0.1)",
            fontFamily: "var(--font-mono)",
            fontSize: 10,
            color: "var(--gray-700)",
            opacity: animate ? 1 : 0,
            transition: `opacity 300ms ease ${300 + i * 50}ms`,
          }}>
            <span style={{ color: "rgba(239,68,68,0.4)", fontSize: 11, fontWeight: 700 }}>✕</span>
            <span>{b.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}