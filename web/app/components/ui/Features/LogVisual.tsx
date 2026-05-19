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
    <div className="overflow-hidden rounded-xl border border-white/10 bg-zinc-950 text-sm">
      <div className="px-4 pt-3 pb-1 text-white/10">{`{`}</div>
      {fields.map((f, i) => (
        <div
          key={f.key}
          className="flex gap-1.5 px-4 pl-6 py-0.5 transition-[opacity,transform] duration-300"
          style={{
            opacity: animate ? 1 : 0,
            transform: animate ? "translateX(0)" : "translateX(-6px)",
            transitionDelay: `${i * 55}ms`,
          }}
        >
          <span className="text-zinc-500">"{f.key}":</span>
          <span style={{ color: f.color }}>{f.val}</span>
          {i < fields.length - 1 && <span className="text-white/10">,</span>}
        </div>
      ))}
      <div className="px-4 pb-3 pt-1 text-white/10">{`}`}</div>
    </div>
  );
}