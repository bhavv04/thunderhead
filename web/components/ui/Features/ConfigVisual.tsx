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
    <div className="overflow-hidden rounded-xl border border-white/10 bg-zinc-950">

      {/* Title bar */}
      <div className="flex items-center gap-1.5 border-b border-white/10 bg-white/5 px-4 py-3">
        {["#ff5f57", "#febc2e", "#28c840"].map((c) => (
          <div key={c} className="h-2.5 w-2.5 rounded-full opacity-75" style={{ background: c }} />
        ))}
        <span className="ml-1.5 text-xs text-zinc-500">
          config.json
        </span>
      </div>

      {/* Lines */}
      <div className="py-3">
        {lines.map((line, i) => (
          <div
            key={i}
            className="flex items-center pr-4 py-0.5 text-sm transition-opacity duration-300"
            style={{
              paddingLeft: 16 + line.indent * 16,
              color: line.color,
              opacity: animate ? 1 : 0,
              transitionDelay: `${i * 40}ms`,
            }}
          >
            <span className="mr-3 min-w-[14px] select-none text-right text-xs text-zinc-700">
              {i + 1}
            </span>
            {line.text}
          </div>
        ))}
      </div>
    </div>
  );
}