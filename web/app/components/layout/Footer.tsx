import { ExternalLink } from "lucide-react";

export default function Footer() {
  return (
    <footer className="px-8 py-16 border-t-2 border-ink bg-ink text-cream">
      <div className="max-w-5xl mx-auto">

        {/* Top row */}
        <div className="flex flex-col md:flex-row justify-between gap-12 mb-12">
          {/* Brand */}
          <div className="max-w-xs">
            <div className="font-black text-2xl tracking-tight mb-3">thunderhead</div>
            <p className="text-cream/50 text-sm leading-relaxed">
              Passive intent-scoring reverse proxy. Silently watches, scores,
              and mitigates bot traffic — no CAPTCHAs, no challenges, just behavior.
            </p>
          </div>

          {/* Links */}
          <div className="flex gap-16">
            <div>
              <div className="text-xs font-bold uppercase tracking-widest text-cream/30 mb-4">
                Project
              </div>
              <div className="flex flex-col gap-3 text-sm">
                <a
                  href="https://github.com/bhavv04/thunderhead"
                  target="_blank"
                  className="text-cream/70 hover:text-cream transition-colors flex items-center gap-1"
                >
                  <ExternalLink size={14} /> GitHub
                </a>
                <a
                  href="https://github.com/bhavv04/thunderhead/blob/main/LICENSE"
                  target="_blank"
                  className="text-cream/70 hover:text-cream transition-colors flex items-center gap-1"
                >
                  <ExternalLink size={14} /> License
                </a>
                <a
                  href="https://github.com/bhavv04/thunderhead/issues"
                  target="_blank"
                  className="text-cream/70 hover:text-cream transition-colors flex items-center gap-1"
                >
                  <ExternalLink size={14} /> Issues
                </a>
              </div>
            </div>

            <div>
              <div className="text-xs font-bold uppercase tracking-widest text-cream/30 mb-4">
                Docs
              </div>
              <div className="flex flex-col gap-3 text-sm">
                <a href="#quickstart" className="text-cream/70 hover:text-cream transition-colors">
                  Quickstart
                </a>
                <a href="#methodology" className="text-cream/70 hover:text-cream transition-colors">
                  Methodology
                </a>
                <a href="#features" className="text-cream/70 hover:text-cream transition-colors">
                  Features
                </a>
              </div>
            </div>
          </div>
        </div>

        {/* Divider */}
        <div className="border-t border-cream/10 pt-8 flex flex-col md:flex-row justify-between items-center gap-4 text-xs text-cream/30">
          <span>© 2026 Bhavdeep Arora. MIT License.</span>
        </div>

      </div>
    </footer>
  );
}