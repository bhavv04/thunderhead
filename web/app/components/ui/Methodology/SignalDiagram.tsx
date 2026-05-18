const SIGNALS = [
  { label: "robots.txt violation",       weight: 30, color: "#ef4444" },
  { label: "Sequential path crawling",   weight: 25, color: "#f97316" },
  { label: "High request rate",          weight: 20, color: "#f59e0b" },
  { label: "Suspicious/missing headers", weight: 15, color: "#a78bfa" },
  { label: "Text-heavy page pattern",    weight: 10, color: "#3b82f6" },
];

export default function SignalDiagram({ animate }: { animate: boolean }) {
  const maxW = 340;
  const rowH = 44;
  const labelW = 200;
  const chartX = labelW + 16;
  const totalH = SIGNALS.length * rowH + 48;

  return (
    <div style={{
      width: "100%",
      overflowX: "auto",
      borderRadius: 12,
      background: "var(--gray-950)",
      border: "1px solid var(--border)",
      padding: "32px 28px",
    }}>
      <svg
        viewBox={`0 0 ${labelW + maxW + 80} ${totalH}`}
        width="100%"
        style={{ display: "block", minWidth: 420, fontFamily: "var(--font-mono)" }}
        aria-label="Thunderhead signal weight breakdown"
      >
        {[0,10,20,30].map((v) => {
          const x = chartX + (v/30) * maxW;
          return (
            <g key={v}>
              <line x1={x} y1={16} x2={x} y2={totalH-32} stroke="rgba(255,255,255,0.04)" strokeWidth={1} />
              <text x={x} y={12} textAnchor="middle" fill="#27272a" fontSize={8} letterSpacing="0.06em">{v}</text>
            </g>
          );
        })}

        {SIGNALS.map((sig, i) => {
          const y = 20 + i * rowH;
          const barW = animate ? (sig.weight / 30) * maxW : 0;
          return (
            <g key={sig.label}>
              <text x={labelW} y={y+14} textAnchor="end"
                fill={animate ? "#a0a0ab" : "#3f3f46"} fontSize={10} letterSpacing="0.01em"
                style={{ transition: `fill 400ms ease ${i*80}ms` }}>
                {sig.label}
              </text>
              <rect x={chartX} y={y+2} width={maxW} height={20} rx={4} fill="rgba(255,255,255,0.03)" />
              <rect x={chartX} y={y+2} width={barW} height={20} rx={4}
                fill={sig.color} fillOpacity={0.8}
                style={{ transition: `width 700ms cubic-bezier(0.16,1,0.3,1) ${120+i*100}ms` }} />
              <text x={chartX+barW+8} y={y+16} fill={sig.color} fontSize={11} fontWeight={700}
                opacity={animate ? 1 : 0}
                style={{ transition: `opacity 300ms ease ${400+i*80}ms` }}>
                +{sig.weight}
              </text>
            </g>
          );
        })}

        <line x1={chartX} y1={totalH-32} x2={chartX+maxW} y2={totalH-32}
          stroke="rgba(255,255,255,0.06)" strokeWidth={1} />
        <text x={chartX+maxW/2} y={totalH-12} textAnchor="middle"
          fill="#27272a" fontSize={9} letterSpacing="0.12em">
          SIGNAL WEIGHTS (score points)
        </text>
      </svg>
    </div>
  );
}