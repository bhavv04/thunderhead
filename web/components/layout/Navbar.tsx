"use client";

import { useState, useEffect } from "react";
import {
  NavLink,
  MobileNavLink,
  GithubButtonDesktop,
  GithubButtonMobile,
  MenuToggle,
} from "@/components/ui/Buttons";

const links = [
  { label: "Methodology", href: "/#methodology" },
  { label: "Features", href: "/#features" },
  { label: "Quickstart", href: "/#quickstart" },
  { label: "Docs", href: "/docs" },
];

const GITHUB_URL = "https://github.com/bhavv04/thunderhead";

const bar =
  "backdrop-blur-xl bg-white/2 transition-colors duration-500";
const barScrolled = "bg-white/5";

const Logo = ({ onClick }: { onClick?: () => void }) => (
  <a href="#top" onClick={onClick} className="flex items-center gap-2 shrink-0">
    <img src="/favicon-192.png" alt="thunderhead" className="h-6 w-6" />
    <span className="text-sm font-medium text-zinc-200 tracking-tight">
      thunderhead
    </span>
  </a>
);

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [active, setActive] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => {
      setScrolled(window.scrollY > 20);
      const current = links
        .map((l) => l.href.slice(1))
        .find(
          (id) =>
            (document.getElementById(id)?.getBoundingClientRect().top ??
              Infinity) <= 120
        );
      setActive(window.scrollY < 80 ? "" : current ?? "");
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const scrollTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
    setMenuOpen(false);
  };

  return (
    <nav className="fixed inset-x-0 top-0 z-50 w-full">
      {/* Desktop */}
      <div
        className={`hidden sm:grid grid-cols-[1fr_auto_1fr] items-center px-6 py-3.5 ${bar} ${
          scrolled ? barScrolled : ""
        }`}
      >
        <Logo />

        <div className="flex items-center gap-1 justify-self-center">
          {links.map(({ label, href }) => (
            <NavLink key={label} href={href} active={active === href.slice(1)}>
              {label}
            </NavLink>
          ))}
        </div>
      </div>

      {/* Mobile */}
      <div className="sm:hidden flex flex-col w-full">
        <div
          className={`flex items-center justify-between px-4 py-3 w-full ${bar} ${
            scrolled ? barScrolled : ""
          }`}
        >
          <Logo onClick={scrollTop} />
          <div className="flex items-center gap-2">
            <MenuToggle open={menuOpen} onToggle={() => setMenuOpen((o) => !o)} />
          </div>
        </div>

        <div
          className={`flex flex-col w-full overflow-hidden ${bar} transition-all duration-300 ease-in-out ${
            menuOpen ? "max-h-56 opacity-100" : "max-h-0 opacity-0 pointer-events-none"
          }`}
        >
          {links.map(({ label, href }) => (
            <MobileNavLink
              key={label}
              href={href}
              active={active === href.slice(1)}
              onClick={() => setMenuOpen(false)}
            >
              {label}
            </MobileNavLink>
          ))}
        </div>
      </div>
    </nav>
  );
}