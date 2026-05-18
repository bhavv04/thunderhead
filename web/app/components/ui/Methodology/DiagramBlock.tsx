import React from "react";
import SectionLabel from "./SectionLabel";
import { useInView } from "./useInView";
import { motion } from "framer-motion";

export default function DiagramBlock({
  label, title, description, children, delay = 0,
}: {
  label: string;
  title: string;
  description: string;
  children: React.ReactNode;
  delay?: number;
}) {
  const { ref, inView } = useInView(0.15);

  return (
    <div ref={ref} style={{
      opacity: inView ? 1 : 0,
      transform: inView ? "translateY(0)" : "translateY(24px)",
      transition: `opacity 700ms ease ${delay}ms, transform 700ms cubic-bezier(0.16,1,0.3,1) ${delay}ms`,
      display: "flex",
      flexDirection: "column",
      gap: 20,
    }}>
      <div>
        <SectionLabel>{label}</SectionLabel>
        <h3 style={{
          fontFamily: "var(--font-sans)",
          fontSize: "var(--text-xl)",
          fontWeight: 600,
          letterSpacing: "-0.03em",
          color: "var(--white)",
          marginBottom: 8,
        }}>
          {title}
        </h3>
        <p style={{
          fontFamily: "var(--font-sans)",
          fontSize: "var(--text-sm)",
          color: "var(--gray-500)",
          lineHeight: 1.65,
          maxWidth: "52ch",
          margin: 0,
        }}>
          {description}
        </p>
      </div>
      <motion.div>{React.cloneElement(children as React.ReactElement, { animate: inView })}</motion.div>
    </div>
  );
}