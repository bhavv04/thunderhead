import LogFeed from "../ui/Logfeed";

export default function Hero() {
  return (
<section className="px-8 py-24 border-b-2 border-ink bg-gradient-to-br from-white to-[#E1E4EF]">
      <div className="max-w-5xl mx-auto">
        
        {/* Top badge */}
        <div className="inline-flex items-center gap-2 bg-punch text-cream text-xs font-bold px-3 py-1.5 rounded-full mb-8 border-2 border-ink shadow-brutal hover:translate-x-[4px] hover:translate-y-[4px] hover:shadow-none transition-all">
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
            View on GitHub →
          </a>
        </div>

        <LogFeed />
      </div>
    </section>
  );
}