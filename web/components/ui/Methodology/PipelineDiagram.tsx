export default function PipelineDiagram({ animate }: { animate: boolean }) {
  const fade = (delay: number): React.CSSProperties => ({
    opacity: animate ? 1 : 0,
    transition: `opacity 400ms ease ${delay}ms`,
  });

  const box = (x: number, y: number, w: number, h: number, accent: string) => (
    <>
      <rect x={x} y={y} width={w} height={h} rx="4" fill="#111" stroke="rgba(255,255,255,0.07)" strokeWidth="0.5" />
      <rect x={x} y={y} width={w} height={4} rx="2" fill={accent} />
    </>
  );

  return (
    <div style={{ width: "100%" }}>
      {/* Desktop horizontal version */}
      <div style={{ width: "100%", overflowX: "auto" }} className="hidden md:block">
        <svg width="100%" viewBox="0 0 680 200" style={{ display: "block", minWidth: 480 }}>
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </marker>
          </defs>

          {/* Request */}
          <g style={fade(0)}>
            {box(10, 72, 110, 56, "#378add")}
            <text x="65" y="94" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={13} fontWeight={500}>Request</text>
            <text x="65" y="112" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={11}>incoming HTTP</text>
          </g>

          {/* Proxy */}
          <g style={fade(90)}>
            {box(165, 72, 110, 56, "#71717a")}
            <text x="220" y="94" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={13} fontWeight={500}>Proxy</text>
            <text x="220" y="112" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={11}>thunderhead</text>
          </g>

          {/* Scorer */}
          <g style={fade(180)}>
            {box(320, 72, 110, 56, "#a78bfa")}
            <text x="375" y="94" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={13} fontWeight={500}>Scorer</text>
            <text x="375" y="112" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={11}>0 – 100 score</text>
          </g>

          {/* Allow */}
          <g style={fade(270)}>
            {box(480, 14, 110, 50, "#22c55e")}
            <text x="535" y="33" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={13} fontWeight={500}>Allow</text>
            <text x="535" y="51" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={11}>score &lt; 40</text>
          </g>

          {/* Tarpit */}
          <g style={fade(360)}>
            {box(480, 75, 110, 50, "#f59e0b")}
            <text x="535" y="94" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={13} fontWeight={500}>Tarpit</text>
            <text x="535" y="112" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={11}>score 40 – 74</text>
          </g>

          {/* Block */}
          <g style={fade(450)}>
            {box(480, 136, 110, 50, "#ef4444")}
            <text x="535" y="155" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={13} fontWeight={500}>Block</text>
            <text x="535" y="173" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={11}>score ≥ 75</text>
          </g>

          {/* Upstream */}
          <g style={fade(540)} opacity={0.4}>
            <rect x="616" y="82" width="58" height="36" rx="4" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="0.5" />
            <text x="645" y="100" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={11}>upstream</text>
          </g>

          {/* Request → Proxy */}
          <line style={fade(200)} x1="120" y1="100" x2="163" y2="100" stroke="#3f3f46" strokeWidth="1.5" markerEnd="url(#arrow)" />

          {/* Proxy → Scorer */}
          <line style={fade(290)} x1="275" y1="100" x2="318" y2="100" stroke="#3f3f46" strokeWidth="1.5" markerEnd="url(#arrow)" />

          {/* Scorer → Allow */}
          <line style={fade(380)} x1="430" y1="88" x2="478" y2="42" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrow)" />

          {/* Scorer → Tarpit */}
          <line style={fade(420)} x1="430" y1="100" x2="478" y2="100" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrow)" />

          {/* Scorer → Block */}
          <line style={fade(460)} x1="430" y1="112" x2="478" y2="158" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrow)" />

          {/* Allow → Upstream */}
          <line style={fade(500)} x1="590" y1="39" x2="644" y2="82" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrow)" />

          {/* Tarpit → Upstream */}
          <line style={fade(520)} x1="590" y1="100" x2="614" y2="100" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrow)" />

          {/* Block → Upstream */}
          <line style={fade(540)} x1="590" y1="161" x2="644" y2="118" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrow)" />
        </svg>
      </div>

      {/* Mobile vertical version */}
      <div style={{ width: "100%" }} className="md:hidden">
        <svg width="100%" viewBox="0 0 300 520" style={{ display: "block" }}>
          <defs>
            <marker id="arrowDown" viewBox="0 0 10 10" refX="5" refY="8" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M1 2L5 8L9 2" fill="none" stroke="context-stroke" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </marker>
          </defs>

          {/* Request */}
          <g style={fade(0)}>
            {box(75, 20, 150, 60, "#378add")}
            <text x="150" y="42" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={12} fontWeight={500}>Request</text>
            <text x="150" y="60" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={10}>incoming HTTP</text>
          </g>

          {/* Proxy */}
          <g style={fade(90)}>
            {box(75, 120, 150, 60, "#71717a")}
            <text x="150" y="142" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={12} fontWeight={500}>Proxy</text>
            <text x="150" y="160" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={10}>thunderhead</text>
          </g>

          {/* Scorer */}
          <g style={fade(180)}>
            {box(75, 220, 150, 60, "#a78bfa")}
            <text x="150" y="242" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={12} fontWeight={500}>Scorer</text>
            <text x="150" y="260" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={10}>0 – 100 score</text>
          </g>

          {/* Allow */}
          <g style={fade(270)}>
            {box(20, 320, 70, 50, "#22c55e")}
            <text x="55" y="340" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={11} fontWeight={500}>Allow</text>
            <text x="55" y="358" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={9}>&lt; 40</text>
          </g>

          {/* Tarpit */}
          <g style={fade(360)}>
            {box(115, 320, 70, 50, "#f59e0b")}
            <text x="150" y="340" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={11} fontWeight={500}>Tarpit</text>
            <text x="150" y="358" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={9}>40 – 74</text>
          </g>

          {/* Block */}
          <g style={fade(450)}>
            {box(210, 320, 70, 50, "#ef4444")}
            <text x="245" y="340" textAnchor="middle" dominantBaseline="central" fill="#f4f4f5" fontSize={11} fontWeight={500}>Block</text>
            <text x="245" y="358" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={9}>≥ 75</text>
          </g>

          {/* Upstream */}
          <g style={fade(540)} opacity={0.4}>
            <rect x="100" y="440" width="100" height="40" rx="4" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="0.5" />
            <text x="150" y="460" textAnchor="middle" dominantBaseline="central" fill="#52525b" fontSize={10}>upstream</text>
          </g>

          {/* Request → Proxy */}
          <line style={fade(200)} x1="150" y1="80" x2="150" y2="118" stroke="#3f3f46" strokeWidth="1.5" markerEnd="url(#arrowDown)" />

          {/* Proxy → Scorer */}
          <line style={fade(290)} x1="150" y1="180" x2="150" y2="218" stroke="#3f3f46" strokeWidth="1.5" markerEnd="url(#arrowDown)" />

          {/* Scorer → Allow */}
          <line style={fade(380)} x1="130" y1="280" x2="55" y2="318" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrowDown)" />

          {/* Scorer → Tarpit */}
          <line style={fade(420)} x1="150" y1="280" x2="150" y2="318" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrowDown)" />

          {/* Scorer → Block */}
          <line style={fade(460)} x1="170" y1="280" x2="245" y2="318" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrowDown)" />

          {/* All → Upstream */}
          <line style={fade(500)} x1="55" y1="370" x2="130" y2="438" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrowDown)" />
          <line style={fade(520)} x1="150" y1="370" x2="150" y2="438" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrowDown)" />
          <line style={fade(540)} x1="245" y1="370" x2="170" y2="438" stroke="#3f3f46" strokeWidth="1.5" strokeDasharray="4 3" markerEnd="url(#arrowDown)" />
        </svg>
      </div>
    </div>
  );
}