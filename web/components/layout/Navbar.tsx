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

const pill =
  "backdrop-blur-xl bg-white/5 transition-all duration-500";
const pillScrolled =
  "backdrop-blur-xl bg-white/8";

const Logo = ({ onClick }: { onClick?: () => void }) => (
  <a href="#top" onClick={onClick} className="px-2 py-1">
    <img src="/favicon-192.png" alt="thunderhead" className="h-6 w-6" />
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
        .find((id) => (document.getElementById(id)?.getBoundingClientRect().top ?? Infinity) <= 120);
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
    <nav className="fixed top-5 left-1/2 -translate-x-1/2 z-50 w-max max-w-[calc(100vw-2rem)]">
      {/* Desktop */}
      <div className={`hidden sm:flex items-center px-2 py-2 rounded-full ${pill} ${scrolled ? pillScrolled : ""}`}>
        <Logo />
        <div className="flex items-center">
          {links.map(({ label, href }) => (
            <NavLink key={label} href={href} active={active === href.slice(1)}>
              {label}
            </NavLink>
          ))}
        </div>
        <GithubButtonDesktop href={GITHUB_URL} />
      </div>

      {/* Mobile */}
      <div className="sm:hidden flex flex-col items-center gap-2">
        <div className={`flex items-center justify-between px-3 py-2 rounded-full w-[calc(100vw-2rem)] ${pill} ${scrolled ? "bg-white/8" : ""}`}>
          <Logo onClick={scrollTop} />
          <div className="flex items-center gap-2">
            <GithubButtonMobile href={GITHUB_URL} />
            <MenuToggle open={menuOpen} onToggle={() => setMenuOpen((o) => !o)} />
          </div>
        </div>

        <div
          className={`flex flex-col w-[calc(100vw-2rem)] rounded-2xl overflow-hidden ${pill} transition-all duration-300 ease-in-out ${
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