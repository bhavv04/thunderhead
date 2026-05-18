"use client";

import { useEffect, useRef, useState } from "react";

// ─── Nav links ───────────────────────────────────────────────
const NAV_LINKS = [
  { label: "How it works", href: "#methodology" },
  { label: "Features",     href: "#features"    },
  { label: "Docs",         href: "#docs"         },
  { label: "Changelog",    href: "#changelog"    },
];

// ─── GitHub star count (static fallback) ────────────────────
const GITHUB_URL = "https://github.com/your-org/thunderhead";

// ─── Logo mark ──────────────────────────────────────────────
function Logo() {
  return (
    <a
      href="/"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 9,
        textDecoration: "none",
        flexShrink: 0,
      }}
    >
      {/* Icon mark */}
      <div
        style={{
          width: 28,
          height: 28,
          borderRadius: 7,
          background: "var(--white)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        {/* Thunderhead bolt */}
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <path
            d="M8.5 1.5L3.5 8H7L5.5 12.5L11 6H7.5L8.5 1.5Z"
            fill="#000"
            strokeLinejoin="round"
          />
        </svg>
      </div>

      <span
        style={{
          fontFamily: "var(--font-sans)",
          fontWeight: 600,
          fontSize: 15,
          letterSpacing: "-0.03em",
          color: "var(--white)",
        }}
      >
        Thunderhead
      </span>
    </a>
  );
}

// ─── GitHub button ───────────────────────────────────────────
function GitHubButton() {
  return (
    <a
      href={GITHUB_URL}
      target="_blank"
      rel="noopener noreferrer"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 7,
        padding: "6px 13px",
        borderRadius: "var(--radius-md)",
        border: "1px solid var(--border)",
        background: "transparent",
        fontFamily: "var(--font-sans)",
        fontSize: 13,
        fontWeight: 500,
        color: "var(--gray-300)",
        textDecoration: "none",
        transition: "border-color 180ms ease, color 180ms ease, background 180ms ease",
        whiteSpace: "nowrap",
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLAnchorElement).style.borderColor = "var(--border-hover)";
        (e.currentTarget as HTMLAnchorElement).style.color = "var(--white)";
        (e.currentTarget as HTMLAnchorElement).style.background = "var(--gray-900)";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLAnchorElement).style.borderColor = "var(--border)";
        (e.currentTarget as HTMLAnchorElement).style.color = "var(--gray-300)";
        (e.currentTarget as HTMLAnchorElement).style.background = "transparent";
      }}
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
      </svg>
      GitHub
    </a>
  );
}

// ─── Hamburger icon ──────────────────────────────────────────
function HamburgerIcon({ open }: { open: boolean }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 18 18"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
    >
      {/* Top line */}
      <line
        x1="2" y1="5" x2="16" y2="5"
        style={{
          transformOrigin: "9px 5px",
          transform: open ? "rotate(45deg) translateY(4px)" : "none",
          transition: "transform 260ms cubic-bezier(0.16,1,0.3,1)",
        }}
      />
      {/* Middle line */}
      <line
        x1="2" y1="9" x2="16" y2="9"
        style={{
          opacity: open ? 0 : 1,
          transition: "opacity 180ms ease",
        }}
      />
      {/* Bottom line */}
      <line
        x1="2" y1="13" x2="16" y2="13"
        style={{
          transformOrigin: "9px 13px",
          transform: open ? "rotate(-45deg) translateY(-4px)" : "none",
          transition: "transform 260ms cubic-bezier(0.16,1,0.3,1)",
        }}
      />
    </svg>
  );
}

// ─── Mobile drawer ───────────────────────────────────────────
function MobileMenu({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  // Lock body scroll while open
  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [open]);

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: "fixed",
          inset: 0,
          zIndex: 40,
          background: "rgba(0,0,0,0.6)",
          backdropFilter: "blur(4px)",
          WebkitBackdropFilter: "blur(4px)",
          opacity: open ? 1 : 0,
          pointerEvents: open ? "auto" : "none",
          transition: "opacity 280ms ease",
        }}
      />

      {/* Drawer panel */}
      <div
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          zIndex: 50,
          width: "min(320px, 88vw)",
          background: "var(--gray-950)",
          borderLeft: "1px solid var(--border)",
          display: "flex",
          flexDirection: "column",
          transform: open ? "translateX(0)" : "translateX(100%)",
          transition: "transform 320ms cubic-bezier(0.16,1,0.3,1)",
          overflowY: "auto",
        }}
      >
        {/* Drawer header */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "16px 20px",
            borderBottom: "1px solid var(--border)",
          }}
        >
          <Logo />
          <button
            onClick={onClose}
            aria-label="Close menu"
            style={{
              background: "none",
              border: "1px solid var(--border)",
              borderRadius: 8,
              padding: "6px 8px",
              cursor: "pointer",
              color: "var(--gray-400)",
              display: "flex",
              alignItems: "center",
              transition: "border-color 180ms ease, color 180ms ease",
            }}
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <line x1="1" y1="1" x2="13" y2="13" />
              <line x1="13" y1="1" x2="1" y2="13" />
            </svg>
          </button>
        </div>

        {/* Nav links */}
        <nav style={{ padding: "8px 12px", flex: 1 }}>
          {NAV_LINKS.map((link, i) => (
            <a
              key={link.href}
              href={link.href}
              onClick={onClose}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "13px 10px",
                borderRadius: 8,
                fontFamily: "var(--font-sans)",
                fontSize: 15,
                fontWeight: 500,
                color: "var(--gray-300)",
                textDecoration: "none",
                borderBottom: i < NAV_LINKS.length - 1
                  ? "1px solid rgba(255,255,255,0.04)"
                  : "none",
                transition: "color 150ms ease, background 150ms ease",
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLAnchorElement).style.color = "var(--white)";
                (e.currentTarget as HTMLAnchorElement).style.background = "rgba(255,255,255,0.04)";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLAnchorElement).style.color = "var(--gray-300)";
                (e.currentTarget as HTMLAnchorElement).style.background = "transparent";
              }}
            >
              {link.label}
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.4 }}>
                <path d="M2.5 6H9.5M6.5 3L9.5 6L6.5 9" />
              </svg>
            </a>
          ))}
        </nav>

        {/* Drawer footer CTA */}
        <div
          style={{
            padding: "16px 20px",
            borderTop: "1px solid var(--border)",
            display: "flex",
            flexDirection: "column",
            gap: 10,
          }}
        >
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 8,
              padding: "11px 16px",
              borderRadius: 8,
              background: "var(--white)",
              color: "var(--black)",
              fontFamily: "var(--font-sans)",
              fontSize: 14,
              fontWeight: 600,
              textDecoration: "none",
              letterSpacing: "-0.01em",
            }}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
            </svg>
            View on GitHub
          </a>

          {/* Quick-start snippet */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "9px 12px",
              borderRadius: 8,
              background: "var(--gray-900)",
              border: "1px solid var(--border)",
            }}
          >
            <span
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: 12,
                color: "var(--gray-300)",
              }}
            >
              <span style={{ color: "var(--gray-600)" }}>$ </span>
              go run ./cmd/thunderhead
            </span>
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Main Navbar ─────────────────────────────────────────────
export default function Navbar() {
  const [scrolled,    setScrolled]    = useState(false);
  const [mobileOpen,  setMobileOpen]  = useState(false);
  const [activeLink,  setActiveLink]  = useState<string | null>(null);
  const navRef = useRef<HTMLElement>(null);

  // Scroll detection — add backdrop blur after 20px
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Close mobile menu on resize to desktop
  useEffect(() => {
    const onResize = () => {
      if (window.innerWidth >= 768) setMobileOpen(false);
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // Close on Escape
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobileOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <>
      <header
        ref={navRef}
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          zIndex: 30,
          height: 58,
          display: "flex",
          alignItems: "center",
          transition: "background 300ms ease, border-color 300ms ease, backdrop-filter 300ms ease",
          background: scrolled
            ? "rgba(0,0,0,0.75)"
            : "transparent",
          backdropFilter: scrolled ? "blur(14px) saturate(180%)" : "none",
          WebkitBackdropFilter: scrolled ? "blur(14px) saturate(180%)" : "none",
          borderBottom: scrolled
            ? "1px solid rgba(255,255,255,0.07)"
            : "1px solid transparent",
        }}
      >
        <div
          style={{
            width: "100%",
            maxWidth: 1200,
            marginInline: "auto",
            paddingInline: 24,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 16,
          }}
        >
          {/* Left — logo */}
          <Logo />

          {/* Centre — desktop nav links */}
          <nav
            aria-label="Primary navigation"
            style={{
              display: "flex",
              alignItems: "center",
              gap: 2,
              // Hide on mobile
              visibility: "visible",
            }}
            className="desktop-nav"
          >
            {NAV_LINKS.map((link) => (
              <a
                key={link.href}
                href={link.href}
                onMouseEnter={() => setActiveLink(link.href)}
                onMouseLeave={() => setActiveLink(null)}
                style={{
                  position: "relative",
                  padding: "6px 12px",
                  borderRadius: 7,
                  fontFamily: "var(--font-sans)",
                  fontSize: 13,
                  fontWeight: 500,
                  letterSpacing: "-0.01em",
                  color: activeLink === link.href
                    ? "var(--white)"
                    : "var(--gray-400)",
                  textDecoration: "none",
                  background: activeLink === link.href
                    ? "rgba(255,255,255,0.06)"
                    : "transparent",
                  transition: "color 150ms ease, background 150ms ease",
                }}
              >
                {link.label}
              </a>
            ))}
          </nav>

          {/* Right — actions */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            {/* GitHub — desktop only */}
            <div className="desktop-only">
              <GitHubButton />
            </div>

            {/* Get started — desktop only */}
            <a
              href="#docs"
              className="desktop-only"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                padding: "6px 14px",
                borderRadius: 8,
                background: "var(--white)",
                color: "var(--black)",
                fontFamily: "var(--font-sans)",
                fontSize: 13,
                fontWeight: 600,
                textDecoration: "none",
                letterSpacing: "-0.01em",
                transition: "background 150ms ease",
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLAnchorElement).style.background = "var(--gray-100)";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLAnchorElement).style.background = "var(--white)";
              }}
            >
              Get started
              <svg width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M2.5 6H9.5M6.5 3L9.5 6L6.5 9" />
              </svg>
            </a>

            {/* Hamburger — mobile only */}
            <button
              aria-label={mobileOpen ? "Close menu" : "Open menu"}
              aria-expanded={mobileOpen}
              onClick={() => setMobileOpen((o) => !o)}
              className="mobile-only"
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                width: 36,
                height: 36,
                borderRadius: 8,
                border: "1px solid var(--border)",
                background: mobileOpen ? "var(--gray-900)" : "transparent",
                cursor: "pointer",
                color: "var(--gray-300)",
                transition: "background 150ms ease, border-color 150ms ease",
                flexShrink: 0,
              }}
            >
              <HamburgerIcon open={mobileOpen} />
            </button>
          </div>
        </div>
      </header>

      {/* Mobile drawer */}
      <MobileMenu open={mobileOpen} onClose={() => setMobileOpen(false)} />

      {/* Responsive style injection */}
      <style>{`
        .desktop-nav  { display: flex; }
        .desktop-only { display: flex; }
        .mobile-only  { display: none; }

        @media (max-width: 767px) {
          .desktop-nav  { display: none !important; }
          .desktop-only { display: none !important; }
          .mobile-only  { display: flex !important; }
        }
      `}</style>
    </>
  );
}