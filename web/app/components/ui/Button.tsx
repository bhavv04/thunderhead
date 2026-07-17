"use client";

import { ArrowUpRight, Menu, X } from "lucide-react";
import { FaGithub } from "react-icons/fa";
import { useState } from "react";

/* ---------- Nav link pill ---------- */

interface NavLinkProps {
  href: string;
  active: boolean;
  children: React.ReactNode;
}

export function NavLink({ href, active, children }: NavLinkProps) {
  return (
    <a
      href={href}
      className={`px-3 py-1.5 rounded-full text-sm transition-all duration-300 ease-in-out ${
        active
          ? "text-white bg-white/15"
          : "text-white/50 hover:text-white/90 hover:bg-white/8"
      }`}
    >
      {children}
    </a>
  );
}

/* ---------- Mobile nav link (list row, not pill) ---------- */

interface MobileNavLinkProps {
  href: string;
  active: boolean;
  onClick?: () => void;
  children: React.ReactNode;
}

export function MobileNavLink({ href, active, onClick, children }: MobileNavLinkProps) {
  return (
    <a
      href={href}
      onClick={onClick}
      className={`px-5 py-3 text-sm border-b border-white/5 last:border-0 transition-all duration-200 ${
        active
          ? "text-white bg-white/10"
          : "text-white/50 hover:text-white hover:bg-white/8"
      }`}
    >
      {children}
    </a>
  );
}

/* ---------- GitHub button (desktop, full "View on GitHub" pill) ---------- */

export function GithubButtonDesktop({ href }: { href: string }) {
  const [hovering, setHovering] = useState(false);

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      onMouseEnter={() => setHovering(true)}
      onMouseLeave={() => setHovering(false)}
      className="ml-1 flex items-center gap-2 px-3 py-1.5 rounded-full text-sm
        bg-white/10 text-white
        hover:bg-white/20 hover:border-white/25
        transition-all duration-300 ease-in-out"
    >
      <span className="flex flex-row gap-1.5"> <FaGithub size={18} className="opacity-70" /> View on GitHub</span>
      <ArrowUpRight
        size={13}
        strokeWidth={2.5}
        className={`transition-all duration-300 ${
          hovering ? "translate-x-0.5 -translate-y-0.5 opacity-100" : "opacity-60"
        }`}
      />
    </a>
  );
}

/* ---------- GitHub button (mobile, compact icon pill) ---------- */

export function GithubButtonMobile({ href }: { href: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs
        bg-white/10 border border-white/15 text-white
        hover:bg-white/20 transition-all duration-300"
    >
      GitHub
      <FaGithub size={11} className="opacity-70" />
    </a>
  );
}

/* ---------- Mobile menu toggle (hamburger / close) ---------- */

interface MenuToggleProps {
  open: boolean;
  onToggle: () => void;
}

export function MenuToggle({ open, onToggle }: MenuToggleProps) {
  return (
    <button
      onClick={onToggle}
      className="w-8 h-8 flex items-center justify-center rounded-full hover:bg-white/10 transition-all duration-300"
      aria-label="Toggle menu"
    >
      {open ? (
        <X size={16} strokeWidth={2.5} className="text-white/70" />
      ) : (
        <Menu size={16} strokeWidth={2.5} className="text-white/70" />
      )}
    </button>
  );
}