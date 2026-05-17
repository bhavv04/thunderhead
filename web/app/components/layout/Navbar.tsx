"use client";

import { useState } from "react";
import { Menu, X } from "lucide-react";

export default function Navbar() {
  const [open, setOpen] = useState(false);

  return (
    <nav className="bg-ink text-cream border-b-2 border-cream sticky top-0 z-50">
      {/* Main row */}
      <div className="flex items-center justify-between px-6 py-4">
        <span className="font-black text-xl tracking-tight"> thunderhead</span>

        {/* Desktop links */}
        <div className="hidden md:flex items-center gap-6 text-sm">
          <a href="#methodology" className="text-cream/70 hover:text-cream transition-colors">
            Methodology
          </a>
          <a href="#features" className="text-cream/70 hover:text-cream transition-colors">
            Features
          </a>
          <a href="#quickstart" className="text-cream/70 hover:text-cream transition-colors">
            Quickstart
          </a>
          <a
          href="https://github.com/bhavv04/thunderhead"
            target="_blank"
            className="bg-ink px-4 py-2 rounded-lg border-2 border-cream font-bold text-sm shadow-[4px_4px_0px_#f8f4ef] hover:shadow-none hover:translate-x-[4px] hover:translate-y-[4px] transition-all"
          >
            GitHub →
          </a>
        </div>

        {/* Mobile hamburger */}
        <button
          className="md:hidden border-2 border-cream rounded-lg p-2 shadow-[4px_4px_0px_#f8f4ef] hover:shadow-none hover:translate-x-[2px] hover:translate-y-[2px] transition-all"
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
            className="bg-ink px-4 py-2 rounded-lg border-2 border-cream font-bold text-sm shadow-[4px_4px_0px_#f8f4ef] hover:shadow-none hover:translate-x-[4px] hover:translate-y-[4px] transition-all text-center"
          >
            GitHub →
          </a>
        </div>
      )}
    </nav>
  );
}