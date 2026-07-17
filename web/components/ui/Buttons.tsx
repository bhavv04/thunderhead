"use client";

import React, { useState } from "react";
import Link from "next/link";
import { ArrowUpRight, Menu, X } from "lucide-react";
import { FaGithub } from "react-icons/fa";
import { Slot } from "@radix-ui/react-slot";
import { cva, VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

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
      <span className="flex flex-row gap-1.5">
        <FaGithub size={18} className="opacity-70" /> View on GitHub
      </span>
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

/* ---------- Rainbow button (primary CTA) ---------- */

const rainbowButtonVariants = cva(
  cn(
    "relative cursor-pointer group transition-all animate-rainbow",
    "inline-flex items-center justify-center gap-2 shrink-0",
    "rounded-sm outline-none focus-visible:ring-[3px] aria-invalid:border-destructive",
    "text-sm font-medium whitespace-nowrap",
    "disabled:pointer-events-none disabled:opacity-50",
    "[&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 [&_svg]:shrink-0"
  ),
  {
    variants: {
      variant: {
        default:
          "border-0 bg-[linear-gradient(#ffffff,#ffffff),linear-gradient(#ffffff_50%,rgba(255,255,255,0.6)_80%,rgba(0,0,0,0)),linear-gradient(90deg,var(--color-1),var(--color-5),var(--color-3),var(--color-4),var(--color-2))] bg-[length:200%] text-primary-foreground [background-clip:padding-box,border-box,border-box] [background-origin:border-box] [border:calc(0.125rem)_solid_transparent] before:absolute before:bottom-[-20%] before:left-1/2 before:z-0 before:h-1/5 before:w-3/5 before:-translate-x-1/2 before:animate-rainbow before:bg-[linear-gradient(90deg,var(--color-1),var(--color-5),var(--color-3),var(--color-4),var(--color-2))] before:bg-[length:200%] before:[filter:blur(0.75rem)] dark:bg-[linear-gradient(#fff,#fff),linear-gradient(#fff_50%,rgba(255,255,255,0.6)_80%,rgba(0,0,0,0)),linear-gradient(90deg,var(--color-1),var(--color-5),var(--color-3),var(--color-4),var(--color-2))]",
        outline:
          "border border-input border-b-transparent bg-[linear-gradient(#ffffff,#ffffff),linear-gradient(#ffffff_50%,rgba(18,18,19,0.6)_80%,rgba(18,18,19,0)),linear-gradient(90deg,var(--color-1),var(--color-5),var(--color-3),var(--color-4),var(--color-2))] bg-[length:200%] text-accent-foreground [background-clip:padding-box,border-box,border-box] [background-origin:border-box] before:absolute before:bottom-[-20%] before:left-1/2 before:z-0 before:h-1/5 before:w-3/5 before:-translate-x-1/2 before:animate-rainbow before:bg-[linear-gradient(90deg,var(--color-1),var(--color-5),var(--color-3),var(--color-4),var(--color-2))] before:bg-[length:200%] before:[filter:blur(0.75rem)] dark:bg-[linear-gradient(#0a0a0a,#0a0a0a),linear-gradient(#0a0a0a_50%,rgba(255,255,255,0.6)_80%,rgba(0,0,0,0)),linear-gradient(90deg,var(--color-1),var(--color-5),var(--color-3),var(--color-4),var(--color-2))]",
      },
      size: {
        default: "h-10 px-4 rounded-xl",
        sm: "h-8 rounded-xl px-3 text-xs",
        lg: "h-11 rounded-xl px-4",
        icon: "size-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

interface RainbowButtonProps
  extends
    React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof rainbowButtonVariants> {
  asChild?: boolean;
}

export const RainbowButton = React.forwardRef<HTMLButtonElement, RainbowButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        data-slot="button"
        className={cn(rainbowButtonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
RainbowButton.displayName = "RainbowButton";

/* ---------- Secondary button (quiet CTA) ---------- */

interface SecondaryButtonProps {
  href: string;
  external?: boolean;
  children: React.ReactNode;
}

export function SecondaryButton({ href, external, children }: SecondaryButtonProps) {
  const className =
    "inline-flex h-11 items-center gap-2 rounded-xl border border-white/15 px-4 text-sm font-medium text-zinc-200 transition-colors hover:border-white/25 hover:bg-white/5";

  if (external) {
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className={className}>
        {children}
      </a>
    );
  }

  return (
    <Link href={href} className={className}>
      {children}
    </Link>
  );
}