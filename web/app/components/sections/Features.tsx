"use client";

import React from "react";
import SectionLabel from "../ui/Methodology/SectionLabel";
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
    <section id="features" style={{
      background: "var(--black)",
      paddingBlock: "var(--space-32)",
      paddingInline: "var(--space-6)",
      position: "relative",
    }}>
      <div style={{
        position: "absolute", top: 0, left: "10%", right: "10%", height: 1,
        background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.06), transparent)",
        pointerEvents: "none",
      }} />

      <div style={{
        width: "100%", maxWidth: 1200, marginInline: "auto",
        display: "flex", flexDirection: "column", gap: 56,
      }}>

        <div ref={headerRef} style={{
          opacity: headerInView ? 1 : 0,
          transform: headerInView ? "translateY(0)" : "translateY(20px)",
          transition: "opacity 700ms ease, transform 700ms cubic-bezier(0.16,1,0.3,1)",
          display: "flex", flexDirection: "column", gap: 14, maxWidth: 560,
        }}>
          <SectionLabel>Features</SectionLabel>
          <h2 style={{
            fontFamily: "var(--font-sans)",
            fontSize: "clamp(1.75rem, 4vw, 2.75rem)",
            fontWeight: 700, letterSpacing: "-0.04em",
            color: "var(--white)", lineHeight: 1.1, margin: 0,
          }}>
            Everything you need.
            <br />
            <span style={{ color: "var(--gray-600)" }}>Nothing you don't.</span>
          </h2>
          <p style={{
            fontFamily: "var(--font-sans)",
            fontSize: "var(--text-base)", color: "var(--gray-500)",
            lineHeight: 1.7, margin: 0,
          }}>
            Thunderhead is deliberately minimal. A single binary, a single config file,
            and a scoring engine that runs entirely in-process — no sidecars, no databases, no SaaS.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 14 }} className="features-grid">
          {FEATURES.map((f) => (
            <FeatureCard key={f.tag} {...f} />
          ))}
        </div>

      </div>

      <style>{`
        @media (max-width: 860px) {
          .features-grid { grid-template-columns: 1fr !important; }
          .feature-wide { grid-column: span 1 !important; }
          .wide-inner { flex-direction: column !important; }
          .wide-text { flex: none !important; border-right: none !important; border-bottom: 1px solid var(--border) !important; }
        }
      `}</style>
    </section>
  );
}