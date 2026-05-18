export default function PipelineDiagram({ animate }: { animate: boolean }) {
  const nodes = [
    { id: "req",    x: 60,  y: 100, label: "Request", sub: "incoming HTTP", color: "#3b82f6" },
    { id: "proxy",  x: 220, y: 100, label: "Proxy",   sub: "thunderhead",   color: "#71717a" },
    { id: "scorer", x: 390, y: 100, label: "Scorer",  sub: "0 – 100 score", color: "#a78bfa" },
    { id: "allow",  x: 570, y: 36,  label: "Allow",   sub: "score < 40",    color: "#22c55e" },
    { id: "tarpit", x: 570, y: 100, label: "Tarpit",  sub: "score ≥ 40",    color: "#f59e0b" },
    { id: "block",  x: 570, y: 164, label: "Block",   sub: "score ≥ 75",    color: "#ef4444" },
  ];

  const lines: [number, number, number, number, string, boolean][] = [
    [128, 100, 172, 100, "#3f3f46", false],
    [298, 100, 342, 100, "#3f3f46", false],
    [458, 88,  530, 52,  "#22c55e", true],
    [458, 100, 530, 100, "#f59e0b", true],
    [458, 112, 530, 148, "#ef4444", true],
  ];

  const upstream = { x: 710, y: 84, w: 90, h: 32 };

  return (
    <div style={{
      width: "100%",
      overflowX: "auto",
      borderRadius: 12,
      background: "var(--gray-950)",
      border: "1px solid var(--border)",
      padding: "32px 24px",
    }}>
      <svg
        viewBox="0 0 840 200"
        width="100%"
        style={{ display: "block", minWidth: 560, fontFamily: "var(--font-mono)" }}
        aria-label="Thunderhead request pipeline diagram"
      >
        <defs>
          {["blue","gray","green","amber","red"].map((id) => {
            const colors: Record<string,string> = {
              blue:"#3b82f6", gray:"#3f3f46",
              green:"#22c55e", amber:"#f59e0b", red:"#ef4444"
            };
            return (
              <marker key={id} id={`arrow-${id}`} markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L0,6 L6,3 z" fill={colors[id]} />
              </marker>
            );
          })}
        </defs>

        {lines.map(([x1,y1,x2,y2,color,dashed], i) => {
          const markerIds: Record<string,string> = {
            "#3f3f46":"gray","#22c55e":"green","#f59e0b":"amber","#ef4444":"red","#3b82f6":"blue"
          };
          return (
            <line
              key={i}
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke={color}
              strokeWidth={1.5}
              strokeDasharray={dashed ? "4 3" : undefined}
              markerEnd={`url(#arrow-${markerIds[color]})`}
              opacity={animate ? 1 : 0}
              style={{ transition: `opacity 400ms ease ${200 + i * 80}ms` }}
            />
          );
        })}

        <line x1={638} y1={36} x2={710} y2={100} stroke="#22c55e" strokeWidth={1.5} strokeDasharray="4 3"
          markerEnd="url(#arrow-green)" opacity={animate ? 1 : 0}
          style={{ transition: "opacity 400ms ease 700ms" }}
        />

        <g opacity={animate ? 1 : 0} style={{ transition: "opacity 400ms ease 760ms" }}>
          <rect x={upstream.x} y={upstream.y} width={upstream.w} height={upstream.h} rx={6}
            fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth={1} />
          <text x={upstream.x + upstream.w/2} y={upstream.y+13} textAnchor="middle" fill="#52525b" fontSize={9} letterSpacing="0.06em">UPSTREAM</text>
          <text x={upstream.x + upstream.w/2} y={upstream.y+25} textAnchor="middle" fill="#3f3f46" fontSize={8}>localhost:3000</text>
        </g>

        {nodes.map((n, i) => (
          <g key={n.id} opacity={animate ? 1 : 0}
            style={{ transition: `opacity 400ms ease ${i * 90}ms` }}>
            <rect x={n.x-56} y={n.y-28} width={112} height={56} rx={8}
              fill="#0c0c0d" stroke={n.color} strokeWidth={1} strokeOpacity={0.4} />
            <rect x={n.x-56} y={n.y-28} width={112} height={3} rx={8} fill={n.color} fillOpacity={0.7} />
            <text x={n.x} y={n.y-6} textAnchor="middle" fill="#e4e4e7" fontSize={11} fontWeight={600} letterSpacing="-0.02em">
              {n.label}
            </text>
            <text x={n.x} y={n.y+10} textAnchor="middle" fill="#52525b" fontSize={8.5} letterSpacing="0.02em">
              {n.sub}
            </text>
          </g>
        ))}

        <text x={420} y={190} textAnchor="middle" fill="#27272a" fontSize={9} letterSpacing="0.12em">
          REQUEST PIPELINE
        </text>
      </svg>
    </div>
  );
}