"use client";

import { useEffect, useState } from "react";
import CopyButton from "../ui/Hero/CopyButton";
import LogFeed from "../ui/Hero/Logfeed";

export default function Hero() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 80);
    return () => clearTimeout(t);
  }, []);

  return (
    <section className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-black px-6 py-24 md:py-32">

      <div className="relative z-10 flex w-full max-w-6xl flex-col gap-12 md:gap-16">

        <div className="grid w-full grid-cols-1 items-center gap-10 md:grid-cols-2 md:gap-12">

          {/* Left: copy */}
          <div className="flex flex-col items-center gap-6 text-center md:items-start md:text-left">
            {/* Badge */}
            <div
              className="transition-[opacity,transform] duration-700"
              style={{
                opacity: mounted ? 1 : 0,
                transform: mounted ? "translateY(0)" : "translateY(12px)",
                transitionDelay: "0ms",
              }}
            >
              <div className="inline-flex items-center border border-white/20 px-3 py-1 text-xs text-zinc-400 rounded-full">
                Open source · No third-party services
              </div>
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
              <a
                href="https://github.com/bhavv04/thunderhead"
                className="btn btn-primary"
              >
                View on GitHub
              </a>

              <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-zinc-950 px-4 py-2">
                <span className="text-sm text-zinc-400">
                  <span className="text-zinc-600">$</span>{" "}
                  <span className="text-zinc-200">go run ./cmd/thunderhead</span>
                </span>
                <CopyButton text="go run ./cmd/thunderhead" />
              </div>
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