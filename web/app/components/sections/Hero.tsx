"use client";

import { useEffect, useState } from "react";
import LogFeed from "../ui/Hero/Logfeed";
import { FiGithub } from "react-icons/fi";
import { RainbowButton } from "@/components/ui/rainbow-button";

export default function Hero() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 80);
    return () => clearTimeout(t);
  }, []);

  return (
    <section className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden px-6 py-24 md:py-32">
      <div className="relative z-10 flex w-full max-w-6xl flex-col gap-12 md:gap-16">
        <div className="grid w-full grid-cols-1 items-center gap-10 md:grid-cols-2 md:gap-12">

          {/* Left: copy */}
          <div className="flex flex-col items-center gap-6 text-center md:items-start md:text-left">
            {/* Badge */}
            <div
              className="transition-[opacity,transform] duration-700 inline-flex items-center gap-2"
              style={{
                opacity: mounted ? 1 : 0,
                transform: mounted ? "translateY(0)" : "translateY(12px)",
                transitionDelay: "0ms",
              }}
            >
              <img src="/thunderhead.png" alt="Thunderhead" className="h-6 w-6 rounded-full" />
            <span className="text-sm text-zinc-400">open source · no third-party software</span>
            </div>

            {/* Headline */}
            <div className="flex max-w-3xl flex-col items-center gap-5 text-center md:items-start md:text-left">
              <h1
                className="text-balance text-4xl font-semibold tracking-tight text-white transition-[opacity,transform] duration-700 md:text-6xl"
                style={{
                  opacity: mounted ? 1 : 0,
                  transform: mounted ? "translateY(0)" : "translateY(12px)",
                  transitionDelay: "80ms",
                }}
              >
                Bots don't belong on your site.
                <br />
                <span className="bg-gradient-to-br from-zinc-200 to-zinc-500 bg-clip-text text-transparent">
                  Bot detection, No JS. No CAPTCHAs.
                </span>
              </h1>

              <p
                className="m-0 max-w-2xl text-base leading-relaxed text-zinc-400 transition-[opacity,transform] duration-700 md:text-lg"
                style={{
                  opacity: mounted ? 1 : 0,
                  transform: mounted ? "translateY(0)" : "translateY(12px)",
                  transitionDelay: "160ms",
                }}
              >
                Thunderhead is a lightweight reverse proxy that silently scores every
                incoming HTTP request 0–100. Bots get tarpitted or blocked.
                Humans never notice.
              </p>
            </div>

            {/* CTAs */}
            <div
              className="flex flex-wrap items-center justify-center gap-3 transition-[opacity,transform] duration-700 md:justify-start"
              style={{
                opacity: mounted ? 1 : 0,
                transform: mounted ? "translateY(0)" : "translateY(12px)",
                transitionDelay: "240ms",
              }}
            >
              <RainbowButton variant="default" asChild size="lg" className="!bg-[linear-gradient(#fff,#fff),linear-gradient(#fff_50%,rgba(255,255,255,0.6)_80%,rgba(0,0,0,0)),linear-gradient(90deg,var(--color-1),var(--color-5),var(--color-3),var(--color-4),var(--color-2))] !text-black">
                <a href="https://github.com/bhavv04/thunderhead" target="_blank" rel="noopener noreferrer">
                    <FiGithub className="size-4" />
                    View on GitHub
                </a>
                </RainbowButton>

            </div>
          </div>

          {/* Right: log feed */}
          <div
            className="transition-[opacity,transform] duration-700"
            style={{
              opacity: mounted ? 1 : 0,
              transform: mounted ? "translateY(0)" : "translateY(12px)",
              transitionDelay: "200ms",
            }}
          >
            <LogFeed />
          </div>

        </div>
      </div>
    </section>
  );
}