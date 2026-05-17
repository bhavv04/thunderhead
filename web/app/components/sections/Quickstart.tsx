const steps = [
  {
    step: "01",
    title: "Install",
    code: "go install github.com/bhavv04/thunderhead/cmd/thunderhead@latest",
    accent: "bg-punch text-cream",
  },
  {
    step: "02",
    title: "Run with defaults",
    code: "thunderhead",
    accent: "bg-signal text-ink",
  },
  {
    step: "03",
    title: "Or point it at your upstream",
    code: "thunderhead -config config.json",
    accent: "bg-warn text-ink",
  },
];

const config = `{
  "listen_addr": ":8080",
  "upstream_url": "http://localhost:3000",
  "thresholds": {
    "tarpit": 40,
    "block": 75
  },
  "allowlist": {
    "ips": [],
    "user_agents": ["Googlebot", "Bingbot"]
  },
  "blocklist": {
    "cidrs": [],
    "ips": []
  }
}`;

export default function Quickstart() {
  return (
    <section id="quickstart" className="px-8 py-24 border-b-2 border-ink bg-cream">
      <div className="max-w-5xl mx-auto">

        {/* Header */}
        <div className="inline-flex items-center gap-2 bg-cream text-ink text-xs font-bold px-3 py-1.5 rounded-full mb-8 border-2 border-ink shadow-brutal">
          Quickstart
        </div>
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-16">
          <h2 className="text-5xl font-black tracking-tighter leading-none max-w-lg">
            Up and running in 60 seconds.
          </h2>
          <p className="text-ink/60 max-w-xs text-sm leading-relaxed">
            Thunderhead sits in front of any HTTP upstream. No code changes
            to your app required.
          </p>
        </div>

        {/* Steps */}
        <div className="flex flex-col gap-4 mb-16">
          {steps.map((s, i) => (
            <div
              key={i}
              className="flex items-center gap-6 border-2 border-ink rounded-xl overflow-hidden shadow-brutal"
            >
              <div className={`${s.accent} font-black text-3xl px-6 self-stretch flex items-center justify-center border-r-2 border-ink min-w-20`}>
                {s.step}
              </div>
              <div className="flex-1 py-4">
                <div className="font-bold text-sm mb-2 text-ink/60 uppercase tracking-widest">
                  {s.title}
                </div>
                <div className="bg-ink text-signal text-sm px-4 py-2 rounded-lg mr-4 whitespace-pre-wrap break-all">
                  $ {s.code}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Config */}
        <div className="border-2 border-ink rounded-xl overflow-hidden shadow-brutal-lg">
          <div className="bg-ink px-6 py-3 flex items-center gap-2 border-b-2 border-ink">
            <span className="w-3 h-3 rounded-full bg-danger border border-ink"></span>
            <span className="w-3 h-3 rounded-full bg-warn border border-ink"></span>
            <span className="w-3 h-3 rounded-full bg-signal border border-ink"></span>
            <span className="ml-2 text-cream/40 font-mono text-xs">config.json</span>
          </div>
          <div className="bg-ink/95 text-zinc-300 font-mono text-sm px-6 py-5 overflow-x-auto">
            <pre>{config}</pre>
          </div>
        </div>

      </div>
    </section>
  );
}