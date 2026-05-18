import SectionLabel from "./SectionLabel";
import { useInView } from "./useInView";

const logLines = [
  `{"time":"2024-01-15T14:23:01Z","ip":"185.220.101.5","path":"/wp-login.php","score":95,"action":"block"}`,
  `{"time":"2024-01-15T14:23:02Z","ip":"64.233.160.0","path":"/blog/post-1","score":22,"action":"allow"}`,
  `{"time":"2024-01-15T14:23:03Z","ip":"198.51.100.7","path":"/robots.txt","score":55,"action":"tarpit"}`,
];

export default function BottomCallout() {
  const { ref, inView } = useInView(0.2);

  return (
    <div ref={ref} style={{
      opacity: inView ? 1 : 0,
      transform: inView ? "translateY(0)" : "translateY(20px)",
      transition: "opacity 700ms ease, transform 700ms cubic-bezier(0.16,1,0.3,1)",
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 48,
      alignItems: "center",
      paddingBlock: 48,
      borderTop: "1px solid var(--border)",
    }}
      className="callout-grid"
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <SectionLabel>Observability</SectionLabel>
        <h3 style={{
          fontFamily: "var(--font-sans)",
          fontSize: "var(--text-2xl)",
          fontWeight: 600,
          letterSpacing: "-0.03em",
          color: "var(--white)",
          margin: 0,
        }}>
          Every decision is a log line.
        </h3>
        <p style={{
          fontFamily: "var(--font-sans)",
          fontSize: 13,
          color: "var(--gray-500)",
          lineHeight: 1.65,
          margin: 0,
          maxWidth: "44ch",
        }}>
          Thunderhead emits structured JSON for every request. Pipe it to
          your existing stack — Grafana, Loki, Datadog, or just{" "}
          <code style={{
            fontFamily: "var(--font-mono)",
            fontSize: 12,
            background: "var(--gray-900)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            padding: "1px 5px",
            color: "var(--gray-300)",
          }}>jq</code>.
        </p>
      </div>

      <div style={{
        background: "var(--gray-950)",
        border: "1px solid var(--border)",
        borderRadius: 12,
        overflow: "hidden",
      }}>
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "10px 14px",
          borderBottom: "1px solid var(--border)",
          background: "rgba(255,255,255,0.02)",
        }}>
          <div style={{ display: "flex", gap: 5 }}>
            {["#ff5f57","#febc2e","#28c840"].map((c) => (
              <div key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c, opacity: 0.8 }} />
            ))}
          </div>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: 10,
            color: "var(--gray-600)",
            letterSpacing: "0.04em",
            marginLeft: 4,
          }}>
            thunderhead.log
          </span>
        </div>

        <div style={{ padding: "12px 16px", display: "flex", flexDirection: "column", gap: 8 }}>
          {logLines.map((line, i) => {
            const parsed = JSON.parse(line);
            const actionColor = parsed.action === "block" ? "#ef4444" : parsed.action === "tarpit" ? "#f59e0b" : "#22c55e";
            return (
              <div key={i} style={{
                fontFamily: "var(--font-mono)",
                fontSize: 10,
                lineHeight: 1.5,
                color: "var(--gray-600)",
                opacity: inView ? 1 : 0,
                transition: `opacity 400ms ease ${300+i*120}ms`,
                display: "flex",
                flexWrap: "wrap",
                gap: "0 4px",
              }}>
                <span style={{ color: "#3f3f46" }}>{`{`}</span>
                <span style={{ color: "#52525b" }}>"action":</span>
                <span style={{ color: actionColor }}>"{parsed.action}"</span>
                <span style={{ color: "#52525b" }}>"score":</span>
                <span style={{ color: "#a78bfa" }}>{parsed.score}</span>
                <span style={{ color: "#52525b" }}>"path":</span>
                <span style={{ color: "var(--gray-400)" }}>"{parsed.path}"</span>
                <span style={{ color: "#3f3f46" }}>{`}`}</span>
              </div>
            );
          })}
        </div>
      </div>

      <style>{`
        .callout-grid { grid-template-columns: 1fr 1fr; }
        @media (max-width: 760px) { .callout-grid { grid-template-columns: 1fr !important; } }
      `}</style>
    </div>
  );
}