"use client";

import SectionLabel from "../ui/SectionLabel";
import Steps from "../ui/Quickstart/Steps";
import InstallTerminal from "@/components/ui/Quickstart/InstallTerminal";
import { useInView } from "@/components/ui/Methodology/useInView";

export default function Quickstart() {
  const { ref: headerRef, inView: headerInView } = useInView(0.2);
  const { ref: stepsRef,  inView: stepsInView  } = useInView(0.15);
  const { ref: termRef,   inView: termInView   } = useInView(0.15);
  const { ref: configRef, inView: configInView } = useInView(0.15);

  return (
    <section id="quickstart" className="relative px-4 md:px-6 py-16 md:py-32">
      <div className="absolute top-0 left-[10%] right-[10%] h-px pointer-events-none" />
      <div className="w-full max-w-6xl mx-auto flex flex-col gap-20">
        {/* Header */}
        <div ref={headerRef} className="flex flex-col gap-4 max-w-lg"
          style={{
            opacity: headerInView ? 1 : 0,
            transform: headerInView ? "translateY(0)" : "translateY(20px)",
            transition: "opacity 700ms ease, transform 700ms cubic-bezier(0.16,1,0.3,1)",
          }}>
          <SectionLabel>Quickstart</SectionLabel>
          <h2 className="text-4xl md:text-5xl font-bold tracking-tight text-white leading-tight m-0">
            Up and running
            <br />
            <span className="text-white/25">in 60 seconds.</span>
          </h2>
          <p className="text-white/40 leading-relaxed m-0">
            Thunderhead sits in front of any HTTP upstream. No code changes
            to your app required — just install, configure, and run.
          </p>
        </div>

        {/* Steps + Terminal */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-12 items-start">
          <div ref={stepsRef}>
            <Steps inView={stepsInView} />
          </div>
          <div ref={termRef} style={{
            opacity: termInView ? 1 : 0,
            transform: termInView ? "translateY(0)" : "translateY(20px)",
            transition: "opacity 700ms ease 100ms, transform 700ms cubic-bezier(0.16,1,0.3,1) 100ms",
          }}>
            <InstallTerminal animate={termInView} />
          </div>
        </div>

      </div>
    </section>
  );
}