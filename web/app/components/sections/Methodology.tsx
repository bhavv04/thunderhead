"use client";

import React from "react";
import SectionLabel from "../ui/Methodology/SectionLabel";
import HowItWorksSteps from "../ui/Methodology/HowItWorksSteps";
import PipelineDiagram from "../ui/Methodology/PipelineDiagram";
import SignalDiagram from "../ui/Methodology/SignalDiagram";
import GaugeDiagram from "../ui/Methodology/GaugeDiagram";
import DiagramBlock from "../ui/Methodology/DiagramBlock";
import BottomCallout from "../ui/Methodology/BottomCallout";
import { useInView } from "../ui/Methodology/useInView";

export default function Methodology() {
  const { ref: headerRef, inView: headerInView } = useInView(0.2);
  const { ref: stepsRef,  inView: stepsInView  } = useInView(0.15);

  return (
    <section id="methodology" style={{
      background: "var(--black)",
      paddingBlock: "var(--space-32)",
      paddingInline: "var(--space-6)",
      position: "relative",
      overflow: "hidden",
    }}>
      <div style={{
        position: "absolute",
        top: 0, left: "10%", right: "10%",
        height: 1,
        background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.06), transparent)",
        pointerEvents: "none",
      }} />

      <div style={{
        width: "100%",
        maxWidth: 1200,
        marginInline: "auto",
        display: "flex",
        flexDirection: "column",
        gap: 80,
      }}>

        {/* Header */}
        <div ref={headerRef} style={{
          display: "flex",
          flexDirection: "column",
          gap: 16,
          maxWidth: 640,
          opacity: headerInView ? 1 : 0,
          transform: headerInView ? "translateY(0)" : "translateY(20px)",
          transition: "opacity 700ms ease, transform 700ms cubic-bezier(0.16,1,0.3,1)",
        }}>
          <SectionLabel>How it works</SectionLabel>
          <h2 style={{
            fontFamily: "var(--font-sans)",
            fontSize: "clamp(1.75rem, 4vw, 2.75rem)",
            fontWeight: 700,
            letterSpacing: "-0.04em",
            color: "var(--white)",
            lineHeight: 1.1,
            margin: 0,
          }}>
            Silent observation.
            <br />
            <span style={{ color: "var(--gray-600)" }}>Graduated response.</span>
          </h2>
          <p style={{
            fontFamily: "var(--font-sans)",
            fontSize: "var(--text-base)",
            color: "var(--gray-500)",
            lineHeight: 1.7,
            margin: 0,
            maxWidth: "52ch",
          }}>
            Thunderhead never interrupts real users. It watches how clients move through
            your site and builds an intent score from passive signals — no fingerprinting,
            no cookies, no third-party calls.
          </p>
        </div>

        {/* Steps + Pipeline */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 48,
          alignItems: "start",
        }} className="methodology-grid">
          <div ref={stepsRef}>
            <SectionLabel>Step by step</SectionLabel>
            <HowItWorksSteps inView={stepsInView} />
          </div>
          <DiagramBlock label="Diagram 01" title="Request pipeline"
            description="Every request enters the proxy, gets scored, and is dispatched to one of three actions — all within a single hop."
            delay={80}>
            <PipelineDiagram animate={false} />
          </DiagramBlock>
        </div>

        {/* Signal weights */}
        <DiagramBlock label="Diagram 02" title="Signal weights"
          description="Five passive signals are sampled per request. Each contributes an additive score. No single signal is decisive — the combination is what matters.">
          <SignalDiagram animate={false} />
        </DiagramBlock>

        {/* Gauge */}
        <DiagramBlock label="Diagram 03" title="Score thresholds"
          description="The final score determines the action tier. Thresholds are configurable in config.json — tune them for your traffic profile.">
          <GaugeDiagram animate={false} />
        </DiagramBlock>

        <BottomCallout />
      </div>

      <style>{`
        .methodology-grid { grid-template-columns: 1fr 1fr; }
        @media (max-width: 860px) { .methodology-grid { grid-template-columns: 1fr !important; } }
      `}</style>
    </section>
  );
}