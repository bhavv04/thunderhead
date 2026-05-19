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
  const labelW = 130;
  const chartX = labelW + 12;
  const totalH = SIGNALS.length * rowH + 48;

  return (
    <div className="w-full">
      <div className="space-y-3 md:hidden">
        {SIGNALS.map((sig, i) => (
          <div key={sig.label} className="rounded-2xl border border-white/10 bg-zinc-950 p-4">
            <div className="mb-2 flex items-center justify-between gap-3">
              <span className="text-sm font-medium text-white/85">{sig.label}</span>
              <span className="text-sm font-semibold" style={{ color: sig.color }}>
                +{sig.weight}
              </span>
            </div>
            <div className="h-2 rounded-full bg-white/5">
              <div
                className="h-2 rounded-full"
                style={{
                  width: animate ? `${(sig.weight / 30) * 100}%` : "0%",
                  backgroundColor: sig.color,
                  transition: `width 700ms cubic-bezier(0.16,1,0.3,1) ${120 + i * 100}ms`,
                }}
              />
            </div>
          </div>
        ))}
      </div>

      <svg
        viewBox={`0 0 ${labelW + maxW + 56} ${totalH}`}
        className="hidden w-full md:block"
        aria-label="Thunderhead signal weight breakdown"
      >
        {[0,10,20,30].map((v) => {
          const x = chartX + (v/30) * maxW;
          return (
            <g key={v}>
              <line x1={x} y1={16} x2={x} y2={totalH-32} stroke="rgba(255,255,255,0.04)" strokeWidth={1} />
              <text x={x} y={12} textAnchor="middle" fill="#52525b" fontSize={8}>{v}</text>
            </g>
          );
        })}

        {SIGNALS.map((sig, i) => {
          const y = 20 + i * rowH;
          const barW = animate ? (sig.weight / 30) * maxW : 0;
          return (
            <g key={sig.label}>
              <text x={labelW} y={y+14} textAnchor="end"
                fill={animate ? "#a0a0ab" : "#52525b"} fontSize={10}
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
          fill="#52525b" fontSize={9}>
        </text>
      </svg>
    </div>
  );
}