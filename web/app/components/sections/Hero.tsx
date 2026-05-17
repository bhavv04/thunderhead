export default function Hero() {
  return (
    <section className="px-8 py-24 border-b-2 border-ink bg-cream">
      <div className="max-w-5xl mx-auto">
        
        {/* Top badge */}
        <div className="inline-flex items-center gap-2 bg-punch text-cream text-xs font-bold px-3 py-1.5 rounded-full mb-8 border-2 border-ink shadow-brutal">
          <span className="w-2 h-2 bg-signal rounded-full animate-pulse"></span>
          Open Source · MIT License
        </div>

        {/* Headline */}
        <h1 className="text-7xl font-black tracking-tighter leading-none mb-6 max-w-3xl">
          Bots don't belong on your site.
        </h1>

        <p className="text-xl text-ink/60 max-w-xl mb-10 leading-relaxed">
          Thunderhead scores the intent of every request — silently, passively, instantly.
          No CAPTCHAs. No Cloudflare. No JS challenges. Just behavior.
        </p>

        {/* CTA row */}
        <div className="flex items-center gap-4 mb-16">
          <a
            href="#quickstart"
            className="bg-punch text-cream font-bold px-6 py-3 rounded-lg border-2 border-ink shadow-brutal hover:shadow-none hover:translate-x-[4px] hover:translate-y-[4px] transition-all"
          >
            Get started →
          </a>
          <a
            href="https://github.com/bhavv04/thunderhead"
            target="_blank"
            className="bg-cream text-ink font-bold px-6 py-3 rounded-lg border-2 border-ink shadow-brutal hover:shadow-none hover:translate-x-[4px] hover:translate-y-[4px] transition-all"
          >
            View on GitHub
          </a>
        </div>

        {/* Diagram */}
        <div className="border-2 border-ink rounded-2xl overflow-hidden shadow-brutal-lg">
          {/* Diagram header */}
          <div className="bg-ink text-cream px-6 py-3 flex items-center gap-2 text-sm font-mono">
            <span className="w-3 h-3 rounded-full bg-danger"></span>
            <span className="w-3 h-3 rounded-full bg-warn"></span>
            <span className="w-3 h-3 rounded-full bg-signal"></span>
            <span className="ml-2 text-cream/40">thunderhead · live</span>
          </div>

          {/* Diagram body */}
          <div className="bg-ink/95 p-8 flex flex-col md:flex-row items-center justify-center gap-4">
            {/* Incoming */}
            <div className="flex flex-col gap-2">
              {["curl/7.88", "Googlebot", "python-requests", "Mozilla/5.0"].map((ua, i) => (
                <div key={i} className="bg-ink border border-cream/20 text-cream/70 font-mono text-xs px-3 py-1.5 rounded">
                  {ua}
                </div>
              ))}
            </div>

            {/* Arrow */}
            <div className="text-cream/30 text-2xl font-black rotate-90 md:rotate-0">→</div>

            {/* Thunderhead box */}
            <div className="bg-punch border-2 border-punch/20 rounded-xl px-6 py-4 text-center">
              <div className="text-cream font-black text-lg">thunderhead</div>
              <div className="text-cream/60 text-xs mt-1 font-mono">scoring engine</div>
            </div>

            {/* Arrow */}
            <div className="text-cream/30 text-2xl font-black rotate-90 md:rotate-0">→</div>

            {/* Outcomes */}
            <div className="flex flex-col gap-2">
              {[
                { label: "allow", score: "12", icon: "✓", style: "text-cream/70 border-signal/40" },
                { label: "allow", score: "8", icon: "✓", style: "text-cream/70 border-signal/40" },
                { label: "tarpit", score: "54", icon: "~", style: "text-warn border-warn/40" },
                { label: "block", score: "91", icon: "✗", style: "text-danger border-danger/40" },
              ].map((item, i) => (
                <div
                  key={i}
                  className={`bg-ink border font-mono text-xs px-3 py-1.5 rounded flex justify-between gap-6 ${item.style}`}
                >
                  <span>{item.icon} {item.label}</span>
                  <span className="opacity-50">score {item.score}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>
    </section>
  );
}