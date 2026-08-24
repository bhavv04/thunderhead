"use client";

import { useEffect, useState } from "react";
import Demo from "@/components/ui/Hero/demo/Demo";
import { FiGithub } from "react-icons/fi";
import { ScrollText } from "lucide-react";
import { Button } from "@/components/ui/Buttons";
import Beams   from "@/components/ui/Background";

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
    <section className="relative isolate overflow-hidden min-h-dvh">
      <div className="absolute inset-x-0 -z-10 pointer-events-none">
        <div style={{ width: '100%', height: '100dvh', position: 'relative' }}>
        <Beams
            beamWidth={3}
            beamHeight={30}
            beamNumber={20}
            lightColor="#ffffff"
            speed={2}
            noiseIntensity={1.75}
            scale={0.2}
            rotation={30}
        />
        </div>
      </div>

      <div className="relative z-10 mx-auto flex w-full max-w-5xl flex-col items-center justify-center gap-16 pt-28 pb-12 px-4">
        <div className="flex flex-col items-center gap-6 text-center w-full">
          <div className="inline-flex items-center gap-2" style={fade(0)}>
            <img src="/reaper.png" alt="Thunderhead" className="h-8 w-8" />
            <span className="text-sm text-zinc-500">
              open source, no third-party software
            </span>
          </div>

          <h1
            className="w-full text-4xl font-bold tracking-tight text-white md:text-5xl md:text-balance"
            style={fade(80)}
          >
            Bots don&apos;t belong on your site.{" "}
            <span className="block md:inline bg-gradient-to-br from-zinc-200 to-zinc-500 bg-clip-text text-transparent">
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

    {/* Dashboard demo — static image on mobile, live demo on desktop */}
        <div
        className="relative z-10 mx-auto w-full max-w-7xl"
        style={fade(360)}
        >
    <div className="md:hidden w-screen relative left-1/2 right-1/2 -mx-[50vw] h-[55vh]">
    <img
        src="/thunderhead_dashboard.png"
        alt="Thunderhead dashboard"
        className="w-full h-full object-cover [object-position:20%_center]"
    />
    </div>

  {/* Desktop: live interactive demo */}
  <div className="hidden md:block relative rounded-l-xl md:rounded-xl overflow-hidden">
    <div className="min-w-7xl">
      <Demo />
    </div>
  </div>
</div>
    </section>
  );
}