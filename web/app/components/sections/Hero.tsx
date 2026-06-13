"use client";

import { useEffect, useState } from "react";
import Demo from "@/app/components/ui/Hero/demo/Demo";
import { FiGithub } from "react-icons/fi";
import { RainbowButton } from "@/components/ui/rainbow-button";

export default function Hero() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 80);
    return () => clearTimeout(t);
  }, []);

  const fade = (delay: number): React.CSSProperties => ({
    opacity: mounted ? 1 : 0,
    transform: mounted ? "translateY(0)" : "translateY(14px)",
    transition: "opacity 0.7s ease, transform 0.7s ease",
    transitionDelay: `${delay}ms`,
  });

  return (
    <section className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden px-6 py-24 md:py-32">
      <div className="relative z-10 flex w-full max-w-5xl flex-col items-center gap-16">

        {/* ── Copy block ── */}
        <div className="flex flex-col items-center gap-6 text-center">

          {/* Badge */}
          <div
            className="inline-flex items-center gap-2"
            style={fade(0)}
          >
            <img
              src="/thunderhead.png"
              alt="Thunderhead"
              className="h-5 w-5 rounded-full"
            />
            <span className="text-sm text-zinc-500">
              open source · no third-party software
            </span>
          </div>

          {/* Headline */}
          <h1
            className="text-balance text-4xl font-semibold tracking-tight text-white md:text-6xl"
            style={fade(80)}
          >
            Bots don't belong on your site.
            <br />
            <span className="bg-gradient-to-br from-zinc-200 to-zinc-500 bg-clip-text text-transparent">
              No JS. No CAPTCHAs.
            </span>
          </h1>

          {/* Sub */}
          <p
            className="max-w-xl text-base leading-relaxed text-zinc-400 md:text-lg"
            style={fade(160)}
          >
            Thunderhead is a lightweight reverse proxy that silently scores every
            incoming HTTP request 0–100. Bots get tarpitted or blocked.
            Humans never notice.
          </p>

          {/* CTA */}
          <div
            className="flex flex-wrap items-center justify-center gap-3"
            style={fade(240)}
          >
            <RainbowButton
              variant="default"
              asChild
              size="lg"
              className="!bg-[linear-gradient(#fff,#fff),linear-gradient(#fff_50%,rgba(255,255,255,0.6)_80%,rgba(0,0,0,0)),linear-gradient(90deg,var(--color-1),var(--color-5),var(--color-3),var(--color-4),var(--color-2))] !text-black"
            >
              <a
                href="https://github.com/bhavv04/thunderhead"
                target="_blank"
                rel="noopener noreferrer"
              >
                <FiGithub className="size-4" />
                View on GitHub
              </a>
            </RainbowButton>
          </div>
        </div>

        {/* ── Dashboard demo ── */}
        <div
          className="w-full -mt-5"
          style={fade(360)}
        >

          {/* Browser chrome frame */}
          <div className="relative rounded-xl bg-neutral-900/40 backdrop-blur-sm overflow-hidden p-2">
            {/* Title bar */}
            <div className="flex items-center gap-2 px-3 py-3">
              <span className="h-3 w-3 rounded-full bg-red-500/70" />
              <span className="h-3 w-3 rounded-full bg-amber-400/70" />
              <span className="h-3 w-3 rounded-full bg-green-500/70" />
            </div>

            {/* Demo */}
            <Demo />
          </div>
        </div>

      </div>
    </section>
  );
}