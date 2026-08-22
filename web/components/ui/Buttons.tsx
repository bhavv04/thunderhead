// components/ui/Buttons.tsx
"use client";

import React from "react";
import { ArrowUpRight, Menu, X } from "lucide-react";
import { FaGithub } from "react-icons/fa";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

/* ---------- Base button ---------- */

const buttonVariants = cva(
  cn(
    "inline-flex items-center justify-center gap-2 shrink-0",
    "rounded-lg text-sm font-medium whitespace-nowrap",
    "transition-colors duration-200 outline-none",
    "focus-visible:ring-1 focus-visible:ring-white/40",
    "disabled:pointer-events-none disabled:opacity-40",
    "[&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 [&_svg]:shrink-0"
  ),
  {
    variants: {
      variant: {
        default: "bg-white text-black hover:bg-white/90",
        outline: "border border-white/15 text-white hover:border-white/30 hover:bg-white/5",
        ghost: "text-white/70 hover:text-white hover:bg-white/5",
      },
      size: {
        default: "h-10 px-4",
        sm: "h-8 px-3 text-xs",
        lg: "h-11 px-5",
        icon: "size-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

export interface ButtonProps
  extends
    React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        data-slot="button"
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

/* ---------- Nav link styles (shared between desktop pill + mobile row) ---------- */

const navLinkVariants = cva(
  "text-sm transition-colors duration-200 outline-none focus-visible:ring-1 focus-visible:ring-white/40",
  {
    variants: {
      variant: {
        desktop: "px-3 py-1.5 rounded-full",
        mobile: "px-5 py-3 border-b border-white/5 last:border-0",
      },
      active: {
        true: "",
        false: "",
      },
    },
    compoundVariants: [
      { variant: "desktop", active: true, className: "text-white" },
      { variant: "desktop", active: false, className: "text-white/45 hover:text-white/85" },
      { variant: "mobile", active: true, className: "text-white bg-white/5" },
      { variant: "mobile", active: false, className: "text-white/45 hover:text-white" },
    ],
    defaultVariants: {
      variant: "desktop",
      active: false,
    },
  }
);

interface BaseNavLinkProps extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  href: string;
  active: boolean;
  children: React.ReactNode;
}

/* ---------- Nav link pill (desktop) ---------- */

export function NavLink({ href, active, children, className, ...props }: BaseNavLinkProps) {
  return (
    <a
      href={href}
      aria-current={active ? "page" : undefined}
      className={cn(navLinkVariants({ variant: "desktop", active }), className)}
      {...props}
    >
      {children}
    </a>
  );
}

/* ---------- Nav link row (mobile menu) ---------- */

export function MobileNavLink({ href, active, children, className, ...props }: BaseNavLinkProps) {
  return (
    <a
      href={href}
      aria-current={active ? "page" : undefined}
      className={cn(navLinkVariants({ variant: "mobile", active }), className)}
      {...props}
    >
      {children}
    </a>
  );
}

/* ---------- GitHub button (desktop) ---------- */

export function GithubButtonDesktop({ href }: { href: string }) {
  return (
    <Button variant="ghost" size="sm" className="ml-1 rounded-full group" asChild>
      <a href={href} target="_blank" rel="noopener noreferrer">
        <FaGithub size={15} className="opacity-70" aria-hidden="true" />
        View on GitHub
        <ArrowUpRight
          size={13}
          strokeWidth={2}
          aria-hidden="true"
          className=""
        />
      </a>
    </Button>
  );
}

/* ---------- GitHub button (mobile) ---------- */

export function GithubButtonMobile({ href }: { href: string }) {
  return (
    <Button variant="outline" size="sm" className="rounded-full gap-1.5 text-white/70 hover:text-white" asChild>
      <a href={href} target="_blank" rel="noopener noreferrer">
        GitHub
        <FaGithub size={11} className="opacity-70" aria-hidden="true" />
      </a>
    </Button>
  );
}

/* ---------- Mobile menu toggle ---------- */

interface MenuToggleProps {
  open: boolean;
  onToggle: () => void;
}

export function MenuToggle({ open, onToggle }: MenuToggleProps) {
  return (
    <Button
      variant="ghost"
      size="icon"
      className="rounded-full text-white/60 hover:text-white"
      onClick={onToggle}
      aria-label={open ? "Close menu" : "Open menu"}
      aria-expanded={open}
    >
      {open ? <X size={16} strokeWidth={2} /> : <Menu size={16} strokeWidth={2} />}
    </Button>
  );
}