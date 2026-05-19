import SectionLabel from "../SectionLabel";
import { useInView } from "./useInView";

const logLines = [
  `{"time":"2024-01-15T14:23:01Z","ip":"185.220.101.5","path":"/wp-login.php","score":95,"action":"block"}`,
  `{"time":"2024-01-15T14:23:02Z","ip":"64.233.160.0","path":"/blog/post-1","score":22,"action":"allow"}`,
  `{"time":"2024-01-15T14:23:03Z","ip":"198.51.100.7","path":"/robots.txt","score":55,"action":"tarpit"}`,
];

const actionColor: Record<string, string> = {
  block:  "#ef4444",
  tarpit: "#f59e0b",
  allow:  "#22c55e",
};

export default function BottomCallout() {
  const { ref, inView } = useInView(0.2);

  return (
    <div
      ref={ref}
      className="grid gap-8 border-t border-white/10 py-10 md:grid-cols-2 md:items-center transition-[opacity,transform] duration-700"
      style={{
        opacity: inView ? 1 : 0,
        transform: inView ? "translateY(0)" : "translateY(20px)",
        transitionTimingFunction: "cubic-bezier(0.16,1,0.3,1)",
      }}
    >
      {/* Left: text */}
      <div className="space-y-3">
        <SectionLabel>Observability</SectionLabel>
        <h3 className="text-2xl font-semibold tracking-tight text-white">
          Every decision is a log line.
        </h3>
        <p className="max-w-md text-sm text-zinc-400 leading-relaxed">
          Thunderhead emits structured JSON for every request. Pipe it to
          your existing stack or just <code>jq</code>.
        </p>
      </div>

      {/* Right: log terminal */}
      <div className="overflow-hidden rounded-xl border border-white/10 bg-zinc-950">
        {/* Title bar */}
        <div className="flex items-center gap-2 border-b border-white/10 bg-white/5 px-4 py-3">
          <div className="flex gap-[5px]">
            {["#ff5f57", "#febc2e", "#28c840"].map((c) => (
              <div
                key={c}
                className="h-2.5 w-2.5 rounded-full opacity-80"
                style={{ background: c }}
              />
            ))}
          </div>
          <span className="ml-1 text-xs text-zinc-500">
            thunderhead.log
          </span>
        </div>

        {/* Log lines */}
        <div className="flex flex-col gap-2 p-4">
          {logLines.map((line, i) => {
            const parsed = JSON.parse(line);
            const color = actionColor[parsed.action] ?? "#a0a0ab";
            return (
              <div
                key={i}
                className="flex flex-wrap gap-x-1 text-xs leading-relaxed text-zinc-500 transition-opacity duration-500"
                style={{
                  opacity: inView ? 1 : 0,
                  transitionDelay: `${300 + i * 120}ms`,
                }}
              >
                <span>{`{`}</span>
                <span>"action":</span>
                <span style={{ color }}>"{parsed.action}"</span>
                <span>"score":</span>
                <span className="text-zinc-300">{parsed.score}</span>
                <span>"path":</span>
                <span className="text-zinc-400">"{parsed.path}"</span>
                <span>{`}`}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}