"use client";

import { useEffect, useState } from "react";
import Demo from "@/components/ui/Hero/demo/Demo";
import { FiGithub } from "react-icons/fi";
import { ScrollText } from "lucide-react";
import { Button } from "@/components/ui/Buttons";
import PixelBlast from "@/components/ui/Background";

const GITHUB_URL = "https://github.com/bhavv04/thunderhead";
const DOCS_URL = "/docs";

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
    <section className="relative isolate overflow-hidden">
      <div className="absolute inset-x-0 h-screen -z-10 pointer-events-none">
        <PixelBlast
          variant="square"
          pixelSize={3}
          color="#B497CF"
          patternScale={2}
          patternDensity={1}
          enableRipples
          rippleIntensityScale={1}
          rippleThickness={0.1}
          rippleSpeed={0.3}
          edgeFade={0.5}
          speed={0.5}
          transparent
          antialias
          autoPauseOffscreen
          style={{ width: "100%", height: "100%" }}
        />
      </div>

      <div className="relative z-10 mx-auto flex w-full max-w-5xl flex-col items-center justify-center gap-16 pt-16 md:pt-28 pb-12 px-4">
        <div className="flex flex-col items-center gap-6 text-center">
          <div className="inline-flex items-center gap-2" style={fade(0)}>
            <img src="/reaper.png" alt="Thunderhead" className="h-8 w-8" />
            <span className="text-sm text-zinc-500">
              open source, no third-party software
            </span>
          </div>

          <h1
            className="text-balance text-4xl font-normal tracking-tight text-white md:text-5xl"
            style={fade(80)}
          >
            Bots don't belong on your site.
            <br />
            <span className="bg-gradient-to-br from-zinc-200 to-zinc-500 bg-clip-text text-transparent">
              No JS. No CAPTCHAs.
            </span>
          </h1>

          <p
            className="max-w-xl text-base leading-relaxed text-zinc-300 text-lg"
            style={fade(160)}
          >
            Thunderhead is a lightweight reverse proxy that silently scores every
            incoming HTTP request 0–100. Bots get tarpitted or blocked.
            Humans never notice.
          </p>

          <div style={fade(240)} className="flex gap-2">
            <Button variant="default" size="default" asChild>
              <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
                <FiGithub className="size-4" />
                View on GitHub
              </a>
            </Button>

            <Button variant="default" size="default" asChild>
              <a href={DOCS_URL}>
                <ScrollText className="size-4" />
                Docs
              </a>
            </Button>
          </div>
        </div>
      </div>

      {/* Dashboard demo */}
      <div
        className="hidden md:block relative z-10 mx-auto w-full max-w-6xl px-4 pb-12"
        style={fade(360)}
      >
        <div className="relative rounded-xl bg-neutral-900 overflow-hidden">
          <Demo />
        </div>
      </div>
    </section>
  );
}