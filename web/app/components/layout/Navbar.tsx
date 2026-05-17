"use client";

import { useState } from "react";
import { Menu, X } from "lucide-react";

export default function Navbar() {
  const [open, setOpen] = useState(false);

  return (
    <nav className="border-b-2 border-ink bg-cream sticky top-0 z-50">
      {/* Main row */}
      <div className="flex items-center justify-between px-6 py-4">
        <span className="font-black text-xl tracking-tight"> thunderhead</span>

        {/* Desktop links */}
        <div className="hidden md:flex items-center gap-8 text-sm font-medium">
          <a href="#methodology" className="hover:text-punch transition-colors">
            Methodology
          </a>
          <a href="#features" className="hover:text-punch transition-colors">
            Features
          </a>
          <a href="#quickstart" className="hover:text-punch transition-colors">
            Quickstart
          </a>
          <a
            href="https://github.com/bhavv04/thunderhead"
            target="_blank"
            className="bg-ink text-cream px-4 py-2 rounded-lg border-2 border-ink shadow-brutal hover:shadow-none hover:translate-x-[4px] hover:translate-y-[4px] transition-all font-bold text-sm"
          >
            GitHub →
          </a>
        </div>

        {/* Mobile hamburger */}
        <button
          className="md:hidden border-2 border-ink rounded-lg p-2 shadow-brutal hover:shadow-none hover:translate-x-[2px] hover:translate-y-[2px] transition-all"
          onClick={() => setOpen(!open)}
        >
          {open ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {/* Mobile menu */}
      {open && (
        <div className="md:hidden border-t-2 border-ink flex flex-col px-6 py-4 gap-4 text-sm font-medium">
          <a
            href="#methodology"
            onClick={() => setOpen(false)}
            className="hover:text-punch transition-colors"
          >
            Methodology
          </a>
          <a
            href="#features"
            onClick={() => setOpen(false)}
            className="hover:text-punch transition-colors"
          >
            Features
          </a>
          <a
            href="#quickstart"
            onClick={() => setOpen(false)}
            className="hover:text-punch transition-colors"
          >
            Quickstart
          </a>
          <a
            href="https://github.com/bhavv04/thunderhead"
            target="_blank"
            className="bg-ink text-cream px-4 py-2 rounded-lg border-2 border-ink text-center font-bold"
          >
            GitHub →
          </a>
        </div>
      )}
    </nav>
  );
}