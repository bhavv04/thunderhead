import React from "react";
import { useInView } from "@/components/ui/Methodology/useInView";

export type FeatureCardProps = {
  tag: string;
  title: string;
  description: string;
  visual: React.ComponentType<{ animate: boolean }>;
  accent?: string;
  delay?: number;
  span?: "normal" | "wide";
};

export default function FeatureCard({
  tag,
  title,
  description,
  visual: Visual,
  accent = "var(--accent)",
  delay = 0,
  span = "normal",
}: FeatureCardProps) {
  const { ref, inView } = useInView(0.12);
  const isWide = span === "wide";

  return (
    <div
      ref={ref}
      className={[
        "flex flex-col overflow-hidden rounded-xl bg-stone-950 transition-[opacity,transform] duration-500",
        isWide ? "md:col-span-2" : "col-span-1",
      ].join(" ")}
      style={{
        opacity: inView ? 1 : 0,
        transform: inView ? "translateY(0)" : "translateY(20px)",
        transitionDelay: `${delay}ms`,
        transitionTimingFunction: "cubic-bezier(0.16,1,0.3,1)",
      }}
    >
      <div className={`flex flex-1 ${isWide ? "flex-col md:flex-row" : "flex-col"}`}>
        <div
          className={[
            "flex flex-col gap-2.5 p-6",
            isWide
              ? "border-b border-white/10 md:w-[320px] md:flex-none md:border-b-0 md:border-r md:border-white/10"
              : "border-b border-white/10",
          ].join(" ")}
        >
          <span
            className="inline-flex items-center gap-2 text-xs"
            style={{ color: accent }}
          >
            {tag}
          </span>

          <h3 className="m-0 whitespace-pre-line text-lg font-semibold tracking-tight text-white leading-tight">
            {title}
          </h3>

          <p className="m-0 text-sm leading-relaxed text-zinc-400">
            {description}
          </p>
        </div>

        <div className="flex flex-1 flex-col justify-center p-4 md:p-5">
          <Visual animate={inView} />
        </div>
      </div>
    </div>
  );
}