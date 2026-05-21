"use client";

import SectionLabel from "../ui/SectionLabel";
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
    <section id="methodology" className="relative overflow-hidden px-6 py-24 md:py-32">

      {/* Top border line */}
      <div className="absolute top-0 left-[10%] right-[10%] h-px pointer-events-none"
        style={{ background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.06), transparent)" }}
      />

      <div className="mx-auto flex w-full max-w-6xl flex-col gap-16 md:gap-20">

        {/* Header */}
        <div
          ref={headerRef}
          className="flex max-w-3xl flex-col gap-4 transition-[opacity,transform] duration-700"
          style={{
            opacity: headerInView ? 1 : 0,
            transform: headerInView ? "translateY(0)" : "translateY(20px)",
            transitionTimingFunction: "cubic-bezier(0.16,1,0.3,1)",
          }}
        >
          <SectionLabel>Methodology</SectionLabel>
          <h2 className="m-0 text-3xl font-semibold tracking-tight text-white leading-tight md:text-4xl">
            Silent observation.
            <br />
            <span className="text-zinc-500">Graduated response.</span>
          </h2>
          <p className="m-0 max-w-2xl text-base leading-relaxed text-zinc-400">
            Thunderhead never interrupts real users. It watches how clients move through
            your site and builds an intent score from passive signals — no fingerprinting,
            no cookies, no third-party calls.
          </p>
        </div>

        {/* Pipeline */}
        <DiagramBlock
          label=""
          title="Request pipeline"
          description="Every request enters the proxy, gets scored, and is dispatched to one of three actions — all within a single hop."
          delay={80}
        >
          <PipelineDiagram animate={false} />
        </DiagramBlock>

        {/* Step by step */}
        <div ref={stepsRef}>
          <SectionLabel>Step by step</SectionLabel>
          <HowItWorksSteps inView={stepsInView} />
        </div>

        {/* Signal weights */}
        <DiagramBlock
          label=""
          title="Signal weights"
          description="Five passive signals are sampled per request. Each contributes an additive score. No single signal is decisive — the combination is what matters."
        >
          <SignalDiagram animate={false} />
        </DiagramBlock>

        {/* Gauge */}
        <DiagramBlock
          label=""
          title="Score thresholds"
          description="The final score determines the action tier. Thresholds are configurable in config.json — tune them for your traffic profile."
        >
          <GaugeDiagram animate={false} />
        </DiagramBlock>

        <BottomCallout />
      </div>
    </section>
  );
}