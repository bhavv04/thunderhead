"use client";

import SectionLabel from "../ui/SectionLabel";
import { useInView } from "../ui/Methodology/useInView";
import FeatureCard, { type FeatureCardProps } from "../ui/Features/FeatureCard";
import PassiveVisual from "../ui/Features/PassiveVisual";
import TarpitVisual from "../ui/Features/TarpitVisual";
import LogVisual from "../ui/Features/LogVisual";
import AllowlistVisual from "../ui/Features/AllowlistVisual";
import ConfigVisual from "../ui/Features/ConfigVisual";
import RoadmapVisual from "../ui/Features/RoadmapVisual";

const FEATURES: FeatureCardProps[] = [
  {
    tag: "Zero friction",
    title: "No JS challenges.\nNo CAPTCHAs.\nNo interruptions.",
    description: "Thunderhead never touches the client. It reads five passive signals from the raw HTTP request — headers, path patterns, request rate — and scores silently in the background.",
    visual: PassiveVisual,
    accent: "#22c55e",
    delay: 0,
    span: "wide",
  },
  {
    tag: "Graduated response",
    title: "Three tiers of action",
    description: "Not every suspicious request deserves a hard block. Tarpitting drains bot resources without revealing detection. Tune thresholds to fit your traffic.",
    visual: TarpitVisual,
    accent: "#f59e0b",
    delay: 60,
    span: "normal",
  },
  {
    tag: "Observability",
    title: "Structured JSON logs",
    description: "Every decision emits a log line with IP, path, score, action, and which signals fired. Pipe to Grafana, Loki, or jq.",
    visual: LogVisual,
    accent: "#a78bfa",
    delay: 120,
    span: "normal",
  },
  {
    tag: "Allowlist",
    title: "IP, CIDR & user-agent bypass",
    description: "Lock out entire CIDR ranges or allowlist trusted crawlers by user-agent. Googlebot never gets tarpitted.",
    visual: AllowlistVisual,
    accent: "#3b82f6",
    delay: 0,
    span: "normal",
  },
  {
    tag: "Configuration",
    title: "Single config file",
    description: "One JSON file controls listen address, upstream URL, score thresholds, tarpit delay, and log output. No env vars required.",
    visual: ConfigVisual,
    accent: "#71717a",
    delay: 60,
    span: "normal",
  },
  {
    tag: "Roadmap",
    title: "What's shipping next",
    description: "Dashboard UI, JS challenge mode, and a Go middleware library are in active development. Core detection is stable and production-ready.",
    visual: RoadmapVisual,
    accent: "var(--accent)",
    delay: 0,
    span: "wide",
  },
];

export default function Features() {
  const { ref: headerRef, inView: headerInView } = useInView(0.2);

  return (
    <section id="features" className="relative px-6 py-24 md:py-32">

      {/* Top border line */}
      <div
        className="absolute top-0 left-[10%] right-[10%] h-px pointer-events-none"
        style={{ background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.06), transparent)" }}
      />

      <div className="mx-auto flex w-full max-w-6xl flex-col gap-12 md:gap-14">

        {/* Header */}
        <div
          ref={headerRef}
          className="flex max-w-2xl flex-col gap-3 transition-[opacity,transform] duration-700"
          style={{
            opacity: headerInView ? 1 : 0,
            transform: headerInView ? "translateY(0)" : "translateY(20px)",
            transitionTimingFunction: "cubic-bezier(0.16,1,0.3,1)",
          }}
        >
          <SectionLabel>Features</SectionLabel>
          <h2 className="m-0 text-3xl font-semibold tracking-tight text-white leading-tight md:text-4xl">
            Everything you need.
            <br />
            <span className="text-zinc-500">Nothing you don't.</span>
          </h2>
          <p className="m-0 text-base leading-relaxed text-zinc-400">
            Thunderhead is deliberately minimal. A single binary, a single config file,
            and a scoring engine that runs entirely in-process — no sidecars, no databases, no SaaS.
          </p>
        </div>

        {/* Grid */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {FEATURES.map((f) => (
            <FeatureCard key={f.tag} {...f} />
          ))}
        </div>

      </div>
    </section>
  );
}