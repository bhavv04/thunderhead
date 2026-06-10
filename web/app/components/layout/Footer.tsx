"use client";

export default function Footer() {
  const projectLinks = [
    { label: "GitHub",  href: "https://github.com/bhavv04/thunderhead" },
    { label: "License", href: "https://github.com/bhavv04/thunderhead/blob/main/LICENSE" },
    { label: "Issues",  href: "https://github.com/bhavv04/thunderhead/issues" },
  ];

  const docLinks = [
    { label: "Quickstart",  href: "#quickstart"  },
    { label: "Methodology", href: "#methodology" },
    { label: "Features",    href: "#features"    },
  ];

  return (
    <footer className="border-t border-white/10 bg-zinc-950/95 backdrop-blur-xl px-6 py-16">
      <div className="mx-auto max-w-6xl">

        {/* Top row */}
        <div className="mb-12 flex flex-wrap justify-between gap-12">

          {/* Brand */}
          <div className="max-w-sm">
            <div className="mb-3 text-white">
              thunderhead
            </div>
            <p className="m-0 max-w-[36ch] text-sm leading-relaxed text-zinc-500">
              Passive intent-scoring reverse proxy. Silently watches, scores,
              and mitigates bot traffic — no CAPTCHAs, no challenges, just behavior.
            </p>
          </div>

          {/* Links */}
          <div className="flex flex-wrap gap-12">
            {[{ title: "Project", links: projectLinks }, { title: "Docs", links: docLinks }].map(({ title, links }) => (
              <div key={title}>
                <div className="mb-4 text-xs uppercase tracking-wide text-zinc-500">
                  {title}
                </div>
                <div className="flex flex-col gap-3">
                  {links.map((link) => (
                    <a
                      key={link.label}
                      href={link.href}
                      target={link.href.startsWith("http") ? "_blank" : undefined}
                      className="text-sm text-zinc-500 no-underline transition-colors duration-150 hover:text-white"
                    >
                      {link.label}
                    </a>
                  ))}
                </div>
              </div>
            ))}
          </div>

        </div>

        {/* Bottom row */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-t border-white/10 pt-8">
          <span className="text-xs text-zinc-600">
            © 2026 Bhavdeep Arora · MIT License
          </span>
        </div>

      </div>
    </footer>
  );
}