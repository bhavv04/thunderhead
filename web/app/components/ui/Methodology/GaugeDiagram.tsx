export default function GaugeDiagram({ animate }: { animate: boolean }) {
  const W = 560, H = 140;
  const trackY = 62, trackH = 20, trackX = 40;
  const trackW = W - 80;
  const allowW  = (40/100) * trackW;
  const tarpitW = (35/100) * trackW;
  const blockW  = (25/100) * trackW;

  const zones = [
    { x: trackX,                    w: allowW,  color: "#22c55e", label: "ALLOW",  range: "0 – 39",   action: "Pass to upstream" },
    { x: trackX+allowW,             w: tarpitW, color: "#f59e0b", label: "TARPIT", range: "40 – 74",  action: "Delay 5s" },
    { x: trackX+allowW+tarpitW,     w: blockW,  color: "#ef4444", label: "BLOCK",  range: "75 – 100", action: "403 Forbidden" },
  ];

  const tick40 = trackX + allowW;
  const tick75 = trackX + allowW + tarpitW;

  return (
    <div style={{
      width: "100%",
      overflowX: "auto",
      borderRadius: 12,
      background: "var(--gray-950)",
      border: "1px solid var(--border)",
      padding: "32px 24px",
    }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%"
        style={{ display: "block", minWidth: 380, fontFamily: "var(--font-mono)" }}
        aria-label="Thunderhead score threshold gauge">
        <defs>
          <clipPath id="track-clip">
            <rect x={trackX} y={trackY} width={trackW} height={trackH} rx={6} />
          </clipPath>
        </defs>

        <rect x={trackX} y={trackY} width={trackW} height={trackH} rx={6}
          fill="#18181b" stroke="rgba(255,255,255,0.06)" strokeWidth={1} />

        {zones.map((z, i) => (
          <rect key={z.label} x={z.x} y={trackY}
            width={animate ? z.w : 0} height={trackH}
            fill={z.color} fillOpacity={0.75} clipPath="url(#track-clip)"
            style={{ transition: `width 700ms cubic-bezier(0.16,1,0.3,1) ${i*120}ms` }} />
        ))}

        {[tick40, tick75].map((x, i) => (
          <line key={i} x1={x} y1={trackY} x2={x} y2={trackY+trackH}
            stroke="rgba(0,0,0,0.5)" strokeWidth={2} />
        ))}

        {[{x:tick40,val:"40"},{x:tick75,val:"75"}].map(({x,val}) => (
          <g key={val} opacity={animate ? 1 : 0} style={{ transition: "opacity 400ms ease 500ms" }}>
            <line x1={x} y1={trackY-4} x2={x} y2={trackY-14} stroke="rgba(255,255,255,0.2)" strokeWidth={1} />
            <text x={x} y={trackY-17} textAnchor="middle" fill="#52525b" fontSize={9} letterSpacing="0.06em">{val}</text>
          </g>
        ))}

        {[0,25,50,75,100].map((v) => {
          const x = trackX + (v/100) * trackW;
          return (
            <g key={v} opacity={animate ? 1 : 0} style={{ transition: "opacity 400ms ease 400ms" }}>
              <line x1={x} y1={trackY+trackH+2} x2={x} y2={trackY+trackH+8}
                stroke="rgba(255,255,255,0.1)" strokeWidth={1} />
              <text x={x} y={trackY+trackH+18} textAnchor="middle" fill="#3f3f46" fontSize={8} letterSpacing="0.04em">{v}</text>
            </g>
          );
        })}

        {zones.map((z, i) => (
          <g key={z.label} opacity={animate ? 1 : 0}
            style={{ transition: `opacity 400ms ease ${300+i*80}ms` }}>
            <text x={z.x+z.w/2} y={trackY+13} textAnchor="middle"
              fill="rgba(0,0,0,0.7)" fontSize={9} fontWeight={700} letterSpacing="0.1em">{z.label}</text>
            <text x={z.x+z.w/2} y={trackY+trackH+32} textAnchor="middle"
              fill={z.color} fontSize={9} fontWeight={600} letterSpacing="0.04em">{z.range}</text>
            <text x={z.x+z.w/2} y={trackY+trackH+46} textAnchor="middle"
              fill="#52525b" fontSize={8.5} letterSpacing="0.02em">{z.action}</text>
          </g>
        ))}

        <text x={W/2} y={H-2} textAnchor="middle" fill="#27272a" fontSize={9} letterSpacing="0.12em">
          INTENT SCORE THRESHOLDS
        </text>
      </svg>
    </div>
  );
}