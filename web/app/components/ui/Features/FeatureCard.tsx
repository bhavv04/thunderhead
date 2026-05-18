import React from "react";
import { useInView } from "../Methodology/useInView";

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
  tag, title, description,
  visual: Visual,
  accent = "var(--accent)",
  delay = 0,
  span = "normal",
}: FeatureCardProps) {
  const { ref, inView } = useInView(0.12);

  return (
    <div ref={ref} style={{
      gridColumn: span === "wide" ? "span 2" : "span 1",
      background: "var(--gray-950)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      overflow: "hidden",
      display: "flex",
      flexDirection: "column",
      opacity: inView ? 1 : 0,
      transform: inView ? "translateY(0)" : "translateY(20px)",
      transition: `opacity 600ms ease ${delay}ms, transform 600ms cubic-bezier(0.16,1,0.3,1) ${delay}ms`,
    }}
      className={span === "wide" ? "feature-wide" : ""}
    >
      <div style={{
        display: "flex",
        flexDirection: span === "wide" ? "row" : "column",
        flex: 1,
      }}
        className={span === "wide" ? "wide-inner" : ""}
      >
        <div style={{
          padding: "28px 28px 24px",
          flex: span === "wide" ? "0 0 340px" : "none",
          display: "flex",
          flexDirection: "column",
          gap: 10,
          borderRight: span === "wide" ? "1px solid var(--border)" : "none",
          borderBottom: span === "wide" ? "none" : "1px solid var(--border)",
        }}
          className={span === "wide" ? "wide-text" : ""}
        >
          <span style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            fontFamily: "var(--font-mono)",
            fontSize: 10, letterSpacing: "0.08em",
            textTransform: "uppercase" as const,
            color: accent, marginBottom: 2,
          }}>
            <span style={{
              display: "inline-block", width: 5, height: 5,
              borderRadius: "50%", background: accent, opacity: 0.7,
            }} />
            {tag}
          </span>

          <h3 style={{
            fontFamily: "var(--font-sans)",
            fontSize: 17, fontWeight: 600,
            letterSpacing: "-0.03em",
            color: "var(--white)",
            lineHeight: 1.2, margin: 0,
            whiteSpace: "pre-line" as const,
          }}>
            {title}
          </h3>

          <p style={{
            fontFamily: "var(--font-sans)",
            fontSize: 13, color: "var(--gray-500)",
            lineHeight: 1.65, margin: 0,
          }}>
            {description}
          </p>
        </div>

        <div style={{
          padding: "20px 20px", flex: 1,
          display: "flex", flexDirection: "column",
          justifyContent: "center",
        }}>
          <Visual animate={inView} />
        </div>
      </div>
    </div>
  );
}