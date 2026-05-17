const signals = [
  {
    signal: "robots.txt violation",
    weight: "+30",
    description: "Client accessed a path explicitly disallowed in robots.txt",
    color: "bg-danger/10 border-danger text-danger",
  },
  {
    signal: "Sequential crawling",
    weight: "+25",
    description: "Paths requested in alphabetical or numeric order — classic scraper pattern",
    color: "bg-danger/10 border-danger text-danger",
  },
  {
    signal: "High request rate",
    weight: "+20",
    description: "More than 30 requests within a 60 second window",
    color: "bg-warn/10 border-warn text-warn",
  },
  {
    signal: "Suspicious headers",
    weight: "+15",
    description: "Missing or bot-like User-Agent, missing Accept or Accept-Language headers",
    color: "bg-warn/10 border-warn text-warn",
  },
  {
    signal: "Text-heavy pattern",
    weight: "+10",
    description: "80%+ of requests hitting only HTML pages — ignoring assets entirely",
    color: "bg-punch/10 border-punch text-punch",
  },
];

const actions = [
  {
    range: "0 – 39",
    action: "Allow",
    description: "Pass through to upstream instantly",
    bg: "bg-signal/80",
    border: "border-ink",
  },
  {
    range: "40 – 74",
    action: "Tarpit",
    description: "Delay response by 5 seconds, waste bot compute",
    bg: "bg-warn/80",
    border: "border-ink",
  },
  {
    range: "75 – 100",
    action: "Block",
    description: "Return 403 Forbidden immediately",
    bg: "bg-danger/80",
    border: "border-ink",
  },
];

export default function Methodology() {
  return (
    <section id="methodology" className="px-6 py-16 md:py-24 border-b-2 border-ink bg-cream">
      <div className="max-w-5xl mx-auto">

        {/* Header */}
        <div className="inline-flex items-center gap-2 bg-cream text-ink text-xs font-bold px-3 py-1.5 rounded-full mb-8 border-2 border-ink shadow-brutal">
          Methodology
        </div>
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-12 md:mb-16">
          <h2 className="text-4xl md:text-5xl font-black tracking-tighter leading-none max-w-lg">
            Every request gets a score. Bots reveal themselves.
          </h2>
          <p className="text-ink/60 max-w-xs text-sm leading-relaxed">
            Thunderhead builds an intent score from 0–100 using behavioral signals.
            Legitimate users score low. Bots score high.
          </p>
        </div>

        {/* Signals */}
        <div className="flex flex-col gap-3 mb-12 md:mb-16">
          {signals.map((s, i) => (
            <div
              key={i}
              className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-6 bg-cream border-2 border-ink rounded-xl px-5 py-4 shadow-brutal hover:translate-x-[2px] hover:translate-y-[2px] hover:shadow-none transition-all"
            >
              <span className={`border-2 font-black text-sm px-3 py-1 rounded-lg w-fit ${s.color}`}>
                {s.weight}
              </span>
              <span className="font-mono text-sm font-bold sm:min-w-48">{s.signal}</span>
              <span className="text-ink/60 text-sm">{s.description}</span>
            </div>
          ))}
        </div>

        {/* Actions */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {actions.map((a, i) => (
            <div
              key={i}
              className={`${a.bg} border-2 ${a.border} rounded-xl p-6 shadow-brutal`}
            >
              <div className="font-black text-2xl mb-1">{a.action}</div>
              <div className="font-mono text-xs mb-3 opacity-70">Score {a.range}</div>
              <div className="text-sm opacity-80">{a.description}</div>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
}