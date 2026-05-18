export default function LogVisual({ animate }: { animate: boolean }) {
  const fields = [
    { key: "time",    val: `"2024-01-15T14:23:01Z"`,            color: "#a78bfa" },
    { key: "ip",      val: `"185.220.101.5"`,                   color: "#f59e0b" },
    { key: "path",    val: `"/wp-login.php"`,                   color: "#3b82f6" },
    { key: "score",   val: `95`,                                color: "#ef4444" },
    { key: "action",  val: `"block"`,                           color: "#ef4444" },
    { key: "signals", val: `["robots_violation","high_rate"]`,  color: "#71717a" },
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
      <div style={{ padding: "10px 14px 6px", color: "rgba(255,255,255,0.08)", fontSize: 13 }}>{`{`}</div>
      {fields.map((f, i) => (
        <div key={f.key} style={{
          padding: "3px 14px 3px 28px",
          display: "flex",
          gap: 6,
          opacity: animate ? 1 : 0,
          transform: animate ? "translateX(0)" : "translateX(-6px)",
          transition: `opacity 300ms ease ${i * 55}ms, transform 300ms ease ${i * 55}ms`,
        }}>
          <span style={{ color: "var(--gray-600)" }}>"{f.key}":</span>
          <span style={{ color: f.color }}>{f.val}</span>
          {i < fields.length - 1 && <span style={{ color: "rgba(255,255,255,0.1)" }}>,</span>}
        </div>
      ))}
      <div style={{ padding: "6px 14px 10px", color: "rgba(255,255,255,0.08)", fontSize: 13 }}>{`}`}</div>
    </div>
  );
}