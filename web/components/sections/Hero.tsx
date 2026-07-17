"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import Demo from "@/components/ui/Hero/demo/Demo";
import { FiGithub } from "react-icons/fi";
import { RainbowButton } from "@/components/ui/Buttons";
import PlasmaWave from "@/components/ui/PlasmaWave";
import { ArrowUpRight } from "lucide-react";

const GITHUB_URL = "https://github.com/bhavv04/thunderhead";

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
    <section className="min-h-screen relative isolate flex flex-col items-center justify-center overflow-hidden px-6 py-24 md:py-32">
      <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden">
        <PlasmaWave />
      </div>

      <div className="relative z-10 flex w-full max-w-5xl flex-col items-center gap-16">
        <div className="flex flex-col items-center gap-6 text-center">

          <div className="inline-flex items-center gap-2" style={fade(0)}>
            <img src="/reaper.png" alt="Thunderhead" className="h-8 w-8" />
            <span className="text-sm text-zinc-500">
              open source, no third-party software
            </span>
          </div>

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

          <p
            className="max-w-xl text-base leading-relaxed text-zinc-400 md:text-lg"
            style={fade(160)}
          >
            Thunderhead is a lightweight reverse proxy that silently scores every
            incoming HTTP request 0–100. Bots get tarpitted or blocked.
            Humans never notice.
          </p>

          <div style={fade(240)}>
            <RainbowButton variant="outline" size="default" className="text-black" asChild>
              <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
                <FiGithub className="size-4" />
                View on GitHub
              </a>
            </RainbowButton>
          </div>
        </div>

        {/* Dashboard demo */}
        <div className="w-full -mt-5" style={fade(360)}>
          <div className="relative rounded-xl bg-neutral-900/40 backdrop-blur-sm overflow-hidden p-2">
            <div className="flex items-center gap-2 px-3 py-3">
              <span className="h-3 w-3 rounded-full bg-red-500/70" />
              <span className="h-3 w-3 rounded-full bg-amber-400/70" />
              <span className="h-3 w-3 rounded-full bg-green-500/70" />
            </div>
            <Demo />
          </div>
        </div>
      </div>
    </section>
  );
}