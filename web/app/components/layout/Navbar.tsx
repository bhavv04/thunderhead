"use client";

import { useState, useEffect } from "react";

const links = [
  { label: "Methodology", href: "#methodology" },
  { label: "Features", href: "#features" },
  { label: "Quickstart", href: "#quickstart" },
];

const GITHUB_URL = "https://github.com/bhavv04/thunderhead";

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [active, setActive] = useState("");
  const [hoveringGithub, setHoveringGithub] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => {
      setScrolled(window.scrollY > 20);

      // Determine active section based on scroll position
      const sectionIds = links.map((l) => l.href.replace("#", ""));
      let current = "";

      for (const id of sectionIds) {
        const el = document.getElementById(id);
        if (el) {
          const rect = el.getBoundingClientRect();
          if (rect.top <= 120) current = id;
        }
      }

      // If scrolled near top, clear active
      if (window.scrollY < 80) current = "";
      setActive(current);
    };

    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const linkClass = (id: string) =>
    `px-4 py-1.5 rounded-full text-sm transition-all duration-300 ease-in-out ${
      active === id
        ? "text-white bg-white/15"
        : "text-white/50 hover:text-white/90 hover:bg-white/8"
    }`;

  return (
    <nav className="fixed top-5 left-1/2 -translate-x-1/2 z-50 w-max max-w-[calc(100vw-2rem)]">
      {/* Desktop */}
      <div
        className={`
          hidden sm:flex items-center gap-1 px-3 py-2 rounded-full
          border border-white/10 backdrop-blur-md bg-white/5
          shadow-[0_0_0_1px_rgba(255,255,255,0.04),0_8px_32px_rgba(0,0,0,0.4)]
          transition-all duration-500 ease-in-out
          ${scrolled ? "bg-white/8 shadow-[0_0_0_1px_rgba(255,255,255,0.08),0_12px_40px_rgba(0,0,0,0.6)]" : ""}
        `}
      >
        <a
          href="#"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          className="px-2 py-1.5 rounded-full text-sm transition-all duration-300 ease-in-out text-white hover:bg-white/10"
        >
          thunderhead
        </a>

        <span className="w-px h-4 bg-white/10 mx-1" />

        {links.map((link) => (
          <a
            key={link.label}
            href={link.href}
            className={linkClass(link.href.replace("#", ""))}
          >
            {link.label}
          </a>
        ))}

        <span className="w-px h-4 bg-white/10 mx-1" />

        <a
          href={GITHUB_URL}
          target="_blank"
          rel="noopener noreferrer"
          onMouseEnter={() => setHoveringGithub(true)}
          onMouseLeave={() => setHoveringGithub(false)}
          className="flex items-center gap-2 px-4 py-1.5 rounded-full text-sm
            bg-white/10 border border-white/15 text-white
            hover:bg-white/20 hover:border-white/25
            transition-all duration-300 ease-in-out overflow-hidden"
        >
          <span>View on GitHub</span>
          <span
            className={`inline-flex transition-transform duration-300 ease-in-out
              ${hoveringGithub ? "translate-x-0.5 -translate-y-0.5" : ""}`}
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="13" height="13"
              viewBox="0 0 24 24"
              fill="none" stroke="currentColor"
              strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
              className={`transition-all duration-300 ${hoveringGithub ? "opacity-100" : "opacity-60"}`}
            >
              <line x1="7" y1="17" x2="17" y2="7" />
              <polyline points="7 7 17 7 17 17" />
            </svg>
          </span>
        </a>
      </div>

      {/* Mobile */}
      <div className="sm:hidden flex flex-col items-center gap-2">
        {/* Mobile pill bar */}
        <div
          className={`
            flex items-center justify-between px-3 py-2 rounded-full w-[calc(100vw-2rem)]
            border border-white/10 backdrop-blur-md bg-white/5
            shadow-[0_0_0_1px_rgba(255,255,255,0.04),0_8px_32px_rgba(0,0,0,0.4)]
            transition-all duration-500
            ${scrolled ? "bg-white/8" : ""}
          `}
        >
          <a
            href="#"
            onClick={() => { window.scrollTo({ top: 0, behavior: "smooth" }); setMenuOpen(false); }}
            className="px-3 py-1 rounded-full text-sm text-white tracking-tight"
          >
            thunderhead
          </a>

          <div className="flex items-center gap-2">
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs
                bg-white/10 border border-white/15 text-white
                hover:bg-white/20 transition-all duration-300"
            >
              GitHub
              <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
                className="opacity-70">
                <line x1="7" y1="17" x2="17" y2="7" />
                <polyline points="7 7 17 7 17 17" />
              </svg>
            </a>

            {/* Hamburger */}
            <button
              onClick={() => setMenuOpen((o) => !o)}
              className="w-8 h-8 flex flex-col items-center justify-center gap-1.5 rounded-full hover:bg-white/10 transition-all duration-300"
              aria-label="Toggle menu"
            >
              <span className={`block w-4 h-px bg-white/70 transition-all duration-300 ${menuOpen ? "rotate-45 translate-y-[3.5px]" : ""}`} />
              <span className={`block w-4 h-px bg-white/70 transition-all duration-300 ${menuOpen ? "-rotate-45 -translate-y-[3.5px]" : ""}`} />
            </button>
          </div>
        </div>

        {/* Mobile dropdown */}
        <div
          className={`
            flex flex-col w-[calc(100vw-2rem)] rounded-2xl overflow-hidden
            border border-white/10 backdrop-blur-md bg-white/5
            transition-all duration-300 ease-in-out
            ${menuOpen ? "max-h-48 opacity-100" : "max-h-0 opacity-0 pointer-events-none"}
          `}
        >
          {links.map((link) => (
            <a
              key={link.label}
              href={link.href}
              onClick={() => setMenuOpen(false)}
              className={`px-5 py-3 text-sm border-b border-white/5 last:border-0 transition-all duration-200
                ${active === link.href.replace("#", "") ? "text-white bg-white/10" : "text-white/50 hover:text-white hover:bg-white/8"}`}
            >
              {link.label}
            </a>
          ))}
        </div>
      </div>
    </nav>
  );
}