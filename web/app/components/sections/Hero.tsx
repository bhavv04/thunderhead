"use client";

import { useEffect, useState } from "react";
import CopyButton from "../ui/Hero/CopyButton";

export default function Hero() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 80);
    return () => clearTimeout(t);
  }, []);

  const fadeUp = (delay: number) => ({
    opacity: mounted ? 1 : 0,
    transform: mounted ? "translateY(0)" : "translateY(12px)",
    transition: `opacity 700ms var(--ease-out) ${delay}ms, transform 700ms var(--ease-out) ${delay}ms`,
  });

  return (
    <section style={{
      position: "relative",
      minHeight: "100vh",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      overflow: "hidden",
      background: "var(--black)",
      paddingBlock: "var(--space-32)",
      paddingInline: "var(--space-6)",
    }}>

      <div style={{
        position: "relative",
        zIndex: 1,
        width: "100%",
        maxWidth: 1200,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: "var(--space-16)",
      }}>

        {/* Badge */}
        <div style={fadeUp(0)}>
          <div style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 8,
            padding: "5px 12px 5px 8px",
            borderRadius: 999,
            border: "1px solid rgba(59,130,246,0.25)",
            background: "rgba(59,130,246,0.07)",
            fontFamily: "var(--font-mono)",
            fontSize: 12,
            letterSpacing: "0.04em",
            color: "var(--accent)",
          }}>
            Open source · No third-party services
          </div>
        </div>

        {/* Headline */}
        <div style={{
          textAlign: "center",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: "var(--space-6)",
          maxWidth: 760,
        }}>
          <h1 style={{
            ...fadeUp(80),
            fontSize: "clamp(2.5rem, 6vw, 4.5rem)",
            letterSpacing: "-0.05em",
            fontWeight: 700,
            lineHeight: 1.05,
            color: "var(--white)",
          }}>
            Bot detection.
            <br />
            <span style={{
              background: "linear-gradient(135deg, var(--gray-200) 0%, var(--gray-500) 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
            }}>
              No JS. No CAPTCHAs.
            </span>
          </h1>

          <p style={{
            ...fadeUp(160),
            fontSize: "var(--text-lg)",
            color: "var(--gray-400)",
            lineHeight: 1.65,
            maxWidth: "52ch",
            margin: 0,
          }}>
            Thunderhead is a lightweight reverse proxy that silently scores every
            incoming HTTP request 0–100. Bots get tarpitted or blocked.
            Humans never notice.
          </p>
        </div>

        {/* CTAs */}
        <div style={{
          ...fadeUp(240),
          display: "flex",
          alignItems: "center",
          gap: "var(--space-3)",
          flexWrap: "wrap",
          justifyContent: "center",
        }}>
          <a href="https://github.com/bhavv04/thunderhead" className="btn btn-primary" style={{ gap: 8 }}>
            View on GitHub
          </a>

          <div style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "9px 14px",
            borderRadius: 8,
            background: "var(--gray-950)",
            border: "1px solid var(--border)",
          }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--gray-400)" }}>
              <span style={{ color: "var(--gray-600)" }}>$</span>{" "}
              <span style={{ color: "var(--gray-200)" }}>go run ./cmd/thunderhead</span>
            </span>
            <CopyButton text="go run ./cmd/thunderhead" />
          </div>
        </div>
      </div>
    </section>
  );
}