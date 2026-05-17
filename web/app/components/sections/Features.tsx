import { ScanSearch, Bot, Shield, HardDrive, LayoutDashboard, Zap } from "lucide-react";

const features = [
  {
    icon: ScanSearch,
    title: "Passive Scoring",
    description:
      "No JS challenges or CAPTCHAs. Thunderhead watches silently and scores behavior without interrupting legitimate users.",
    accent: "bg-punch/40 border-punch",
  },
  {
    icon: Bot,
    title: "robots.txt Aware",
    description:
      "Automatically fetches and parses your upstream's robots.txt on startup. Violations immediately spike the intent score.",
    accent: "bg-signal/40 border-signal",
  },
  {
    icon: Shield,
    title: "Allowlist & Blocklist",
    description:
      "Whitelist Googlebot, Bingbot, and trusted IPs. Block known bad actors by IP or entire CIDR subnet ranges.",
    accent: "bg-warn/40 border-warn",
  },
  {
    icon: HardDrive,
    title: "Persistent State",
    description:
      "Client scores survive restarts. Thunderhead saves state to disk and reloads on startup — bans don't reset.",
    accent: "bg-danger/40 border-danger",
  },
  {
    icon: LayoutDashboard,
    title: "Live Dashboard",
    description:
      "Built-in dashboard at /thunderhead/status shows live scores, request counts, and actions per IP in real time.",
    accent: "bg-punch/40 border-punch",
  },
  {
    icon: Zap,
    title: "Single Binary",
    description:
      "One Go binary, zero external dependencies. Drop it in front of any HTTP upstream and you're protected.",
    accent: "bg-signal/40 border-signal",
  },
];


export default function Features() {
  return (
    <section id="features" className="px-8 py-24 border-b-2 border-ink bg-cream">
      <div className="max-w-5xl mx-auto">

        {/* Header */}
        <div className="inline-flex items-center gap-2 bg-cream text-ink text-xs font-bold px-3 py-1.5 rounded-full mb-8 border-2 border-ink shadow-brutal">
          Features
        </div>
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-16">
          <h2 className="text-5xl font-black tracking-tighter leading-none max-w-lg">
            Everything built in. Nothing bolted on.
          </h2>
          <p className="text-ink/60 max-w-xs text-sm leading-relaxed">
            Thunderhead ships as a single binary with everything included — no plugins,
            no config hell, no third-party accounts required.
          </p>
        </div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {features.map((f, i) => (
            <div
              key={i}
              className={`border-2 ${f.accent} rounded-xl p-6 shadow-brutal hover:translate-x-[4px] hover:translate-y-[4px] hover:shadow-none transition-all bg-cream`}
            >
              <div className="mb-4">
                <f.icon size={28} strokeWidth={2} />
              </div>
              <h3 className="font-black text-lg mb-2 tracking-tight">{f.title}</h3>
              <p className="text-ink/60 text-sm leading-relaxed">{f.description}</p>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
}