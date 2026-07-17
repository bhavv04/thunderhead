import React from "react";
import SectionLabel from "@/components/ui/SectionLabel";
import { useInView } from "./useInView";

export default function DiagramBlock({
  label, title, description, children, delay = 0,
}: {
  label: string;
  title: string;
  description: string;
  children: React.ReactElement<any>;
  delay?: number;
}) {
  const { ref, inView } = useInView(0.15);

  return (
    <div
      ref={ref}
      className="flex flex-col gap-4 transition-[opacity,transform] duration-700"
      style={{
        opacity: inView ? 1 : 0,
        transform: inView ? "translateY(0)" : "translateY(24px)",
        transitionDelay: `${delay}ms`,
        transitionTimingFunction: "cubic-bezier(0.16,1,0.3,1)",
      }}
    >
      <div className="space-y-2">
        <SectionLabel>{label}</SectionLabel>
        <h3 className="text-xl font-semibold tracking-tight text-white">
          {title}
        </h3>
        <p className="max-w-2xl text-sm text-zinc-400 leading-relaxed">
          {description}
        </p>
      </div>
      <div>{React.cloneElement(children, { animate: inView } as any)}</div>
    </div>
  );
}