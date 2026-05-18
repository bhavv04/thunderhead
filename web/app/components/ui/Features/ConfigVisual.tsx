export default function ConfigVisual({ animate }: { animate: boolean }) {
  const lines = [
    { indent: 0, text: `{`,                                       color: "rgba(255,255,255,0.12)" },
    { indent: 1, text: `"listen_addr":  ":8080",`,                color: "var(--gray-400)" },
    { indent: 1, text: `"upstream_url": "http://localhost:3000",`, color: "var(--gray-400)" },
    { indent: 1, text: `"thresholds": {`,                         color: "var(--gray-500)" },
    { indent: 2, text: `"tarpit": 40,`,                           color: "#f59e0b" },
    { indent: 2, text: `"block":  75`,                            color: "#ef4444" },
    { indent: 1, text: `},`,                                      color: "var(--gray-500)" },
    { indent: 1, text: `"tarpit": {`,                             color: "var(--gray-500)" },
    { indent: 2, text: `"delay": 5000000000`,                     color: "#a78bfa" },
    { indent: 1, text: `},`,                                      color: "var(--gray-500)" },
    { indent: 1, text: `"log_file": ""`,                          color: "var(--gray-600)" },
    { indent: 0, text: `}`,                                       color: "rgba(255,255,255,0.12)" },
  ];

  return (
    <div style={{
      background: "var(--gray-950)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      overflow: "hidden",
    }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 6,
        padding: "8px 12px",
        borderBottom: "1px solid var(--border)",
        background: "rgba(255,255,255,0.015)",
      }}>
        {["#ff5f57","#febc2e","#28c840"].map((c) => (
          <div key={c} style={{ width: 9, height: 9, borderRadius: "50%", background: c, opacity: 0.75 }} />
        ))}
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--gray-600)", marginLeft: 6, letterSpacing: "0.04em" }}>
          config.json
        </span>
      </div>
      <div style={{ padding: "10px 0" }}>
        {lines.map((line, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center",
            paddingBlock: 1,
            paddingLeft: 14 + line.indent * 16,
            paddingRight: 14,
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            color: line.color,
            opacity: animate ? 1 : 0,
            transition: `opacity 250ms ease ${i * 40}ms`,
          }}>
            <span style={{ color: "var(--gray-800)", fontSize: 9, marginRight: 12, minWidth: 14, textAlign: "right" as const, userSelect: "none" as const }}>
              {i + 1}
            </span>
            {line.text}
          </div>
        ))}
      </div>
    </div>
  );
}