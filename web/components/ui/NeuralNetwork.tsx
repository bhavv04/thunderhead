const CONFIG = {
  hero: {
    nodeRadius: 3,
    nodeOpacity: 0.9,
    lineOpacity: 0.16,
    glowOpacity: 0.12,
  },
  preview: {
    nodeRadius: 2.5,
    nodeOpacity: 0.8,
    lineOpacity: 0.13,
    glowOpacity: 0.1,
  },
  thumbnail: {
    nodeRadius: 3.5,
    nodeOpacity: 1,
    lineOpacity: 0.24,
    glowOpacity: 0.18,
  },
} as const;

// Landscape: wide viewBox, layers arranged left → right (your original)
const LAYERS_LANDSCAPE = [
  [[120, 140], [120, 240], [120, 340], [120, 440]],
  [[280, 100], [280, 180], [280, 260], [280, 340], [280, 420], [280, 500]],
  [[450, 130], [450, 220], [450, 310], [450, 400], [450, 490]],
  [[650, 170], [650, 300], [650, 430]],
] as const;

// Portrait: tall viewBox, same layers rotated to run top → bottom
const LAYERS_PORTRAIT = [
  [[140, 120], [240, 120], [340, 120], [440, 120]],
  [[100, 280], [180, 280], [260, 280], [340, 280], [420, 280], [500, 280]],
  [[130, 450], [220, 450], [310, 450], [400, 450], [490, 450]],
  [[170, 650], [300, 650], [430, 650]],
] as const;

type NeuralNetworkVariant = keyof typeof CONFIG;
type Orientation = "landscape" | "portrait";

function NeuralNetworkSvg({
  variant,
  orientation,
}: {
  variant: NeuralNetworkVariant;
  orientation: Orientation;
}) {
  const config = CONFIG[variant];
  const LAYERS = orientation === "portrait" ? LAYERS_PORTRAIT : LAYERS_LANDSCAPE;
  const viewBox = orientation === "portrait" ? "0 0 600 800" : "0 0 800 600";
  const highlight1 = orientation === "portrait" ? [310, 450] : [450, 310];
  const highlight2 = orientation === "portrait" ? [300, 650] : [650, 300];

  return (
    <svg
      className="absolute inset-0 h-full w-full"
      viewBox={viewBox}
      preserveAspectRatio="xMidYMid slice"
    >
      {/* Connections */}
      {LAYERS.slice(0, -1).map((layer, i) =>
        layer.map(([x1, y1], a) =>
          LAYERS[i + 1].map(([x2, y2], b) => (
            <line
              key={`${i}-${a}-${b}`}
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke="var(--color-bg-line)"
              strokeWidth="1"
              opacity={config.lineOpacity}
            />
          ))
        )
      )}

      {/* Nodes */}
      {LAYERS.flat().map(([x, y], i) => (
        <circle
          key={i}
          cx={x}
          cy={y}
          r={config.nodeRadius}
          fill="var(--color-bg-foreground)"
          opacity={config.nodeOpacity}
        />
      ))}

      {/* Highlighted neurons */}
      <circle cx={highlight1[0]} cy={highlight1[1]} r={config.nodeRadius + 2} fill="var(--color-bg-accent)" />
      <circle cx={highlight2[0]} cy={highlight2[1]} r={config.nodeRadius + 1.5} fill="var(--color-bg-secondary)" />
    </svg>
  );
}

export default function NeuralNetwork({
  variant = "hero",
}: {
  variant?: NeuralNetworkVariant;
}) {
  const config = CONFIG[variant];

  return (
    <div className="absolute inset-0 overflow-hidden bg-bg-canvas">
      {/* Mobile: portrait layout */}
      <div className="absolute inset-0 sm:hidden">
        <NeuralNetworkSvg variant={variant} orientation="portrait" />
      </div>

      {/* sm and up: landscape layout */}
      <div className="absolute inset-0 hidden sm:block">
        <NeuralNetworkSvg variant={variant} orientation="landscape" />
      </div>

      {/* Soft AI glow */}
      <div
        className="absolute inset-0"
        style={{
          opacity: config.glowOpacity,
          background: `
            radial-gradient(circle at 56% 52%, var(--color-bg-accent) 0%, transparent 22%),
            radial-gradient(circle at 81% 50%, var(--color-bg-secondary) 0%, transparent 18%)
          `,
          filter: "blur(48px)",
          mixBlendMode: "screen",
        }}
      />
    </div>
  );
}