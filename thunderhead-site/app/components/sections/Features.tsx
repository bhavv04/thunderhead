const features = [
  {
    icon: "",
    title: "Passive Scoring",
    description:
      "No JS challenges or CAPTCHAs. Thunderhead watches silently and scores behavior without interrupting legitimate users.",
  },
  {
    icon: "",
    title: "robots.txt Aware",
    description:
      "Automatically fetches and parses your upstream's robots.txt on startup. Violations immediately spike the intent score.",
  },
  {
    icon: "",
    title: "Allowlist & Blocklist",
    description:
      "Whitelist Googlebot, Bingbot, and trusted IPs. Block known bad actors by IP or entire CIDR subnet ranges.",
  },
  {
    icon: "",
    title: "Persistent State",
    description:
      "Client scores survive restarts. Thunderhead saves state to disk and reloads it on startup — bans don't reset.",
  },
  {
    icon: "",
    title: "Live Dashboard",
    description:
      "Built-in dashboard at /thunderhead/status shows live scores, request counts, and actions per IP in real time.",
  },
  {
    icon: "",
    title: "Single Binary",
    description:
      "One Go binary, zero external dependencies. Drop it in front of any HTTP upstream and you're protected.",
  },
];

export default function Features() {
  return (
    <section id="features" className="px-8 py-24 border-b border-black">
      <div className="max-w-4xl mx-auto">
        <div className="inline-block bg-black text-white text-xs font-bold px-3 py-1 rounded-full mb-6 uppercase tracking-widest">
          Features
        </div>
        <h2 className="text-4xl font-black tracking-tighter mb-4">
          Everything you need, nothing you don't.
        </h2>
        <p className="text-zinc-600 mb-16 max-w-xl">
          Thunderhead ships as a single binary with everything built in — no plugins,
          no config hell, no third-party accounts.
        </p>

        <div className="grid grid-cols-3 gap-4">
          {features.map((f, i) => (
            <div
              key={i}
              className="border border-black rounded-xl p-6 hover:bg-yellow-50 transition-colors"
            >
              <div className="text-3xl mb-4">{f.icon}</div>
              <h3 className="font-bold text-sm mb-2">{f.title}</h3>
              <p className="text-zinc-600 text-sm leading-relaxed">{f.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}