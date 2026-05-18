"use client";

export default function Footer() {
  return (
    <footer style={{
      borderTop: "1px solid var(--border)",
      background: "var(--gray-950)",
      paddingBlock: "var(--space-16)",
      paddingInline: "var(--space-6)",
    }}>
      <div style={{ maxWidth: 1200, marginInline: "auto" }}>

        {/* Top row */}
        <div style={{
          display: "flex",
          flexDirection: "row",
          justifyContent: "space-between",
          gap: "var(--space-12)",
          marginBottom: "var(--space-12)",
          flexWrap: "wrap",
        }}>

          {/* Brand */}
          <div style={{ maxWidth: 300 }}>
            <div style={{
              fontFamily: "var(--font-sans)",
              fontSize: "var(--text-base)",
              fontWeight: 600,
              color: "var(--white)",
              letterSpacing: "-0.02em",
              marginBottom: "var(--space-3)",
            }}>
              thunderhead
            </div>
            <p style={{
              fontFamily: "var(--font-sans)",
              fontSize: "var(--text-sm)",
              color: "var(--gray-600)",
              lineHeight: 1.65,
              margin: 0,
              maxWidth: "36ch",
            }}>
              Passive intent-scoring reverse proxy. Silently watches, scores,
              and mitigates bot traffic — no CAPTCHAs, no challenges, just behavior.
            </p>
          </div>

          {/* Links */}
          <div style={{ display: "flex", gap: "var(--space-16)", flexWrap: "wrap" }}>

            <div>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                letterSpacing: "0.1em",
                textTransform: "uppercase" as const,
                color: "var(--gray-700)",
                marginBottom: "var(--space-4)",
              }}>
                Project
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
                {[
                  { label: "GitHub",  href: "https://github.com/bhavv04/thunderhead" },
                  { label: "License", href: "https://github.com/bhavv04/thunderhead/blob/main/LICENSE" },
                  { label: "Issues",  href: "https://github.com/bhavv04/thunderhead/issues" },
                ].map((link) => (
                  <a key={link.label} href={link.href} target="_blank" style={{
                    fontFamily: "var(--font-sans)",
                    fontSize: "var(--text-sm)",
                    color: "var(--gray-500)",
                    textDecoration: "none",
                    transition: "color var(--duration-fast) var(--ease-out)",
                  }}
                    onMouseEnter={(e) => (e.currentTarget.style.color = "var(--white)")}
                    onMouseLeave={(e) => (e.currentTarget.style.color = "var(--gray-500)")}
                  >
                    {link.label}
                  </a>
                ))}
              </div>
            </div>

            <div>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--text-xs)",
                letterSpacing: "0.1em",
                textTransform: "uppercase" as const,
                color: "var(--gray-700)",
                marginBottom: "var(--space-4)",
              }}>
                Docs
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
                {[
                  { label: "Quickstart",   href: "#quickstart"   },
                  { label: "Methodology",  href: "#methodology"  },
                  { label: "Features",     href: "#features"     },
                ].map((link) => (
                  <a key={link.label} href={link.href} style={{
                    fontFamily: "var(--font-sans)",
                    fontSize: "var(--text-sm)",
                    color: "var(--gray-500)",
                    textDecoration: "none",
                    transition: "color var(--duration-fast) var(--ease-out)",
                  }}
                    onMouseEnter={(e) => (e.currentTarget.style.color = "var(--white)")}
                    onMouseLeave={(e) => (e.currentTarget.style.color = "var(--gray-500)")}
                  >
                    {link.label}
                  </a>
                ))}
              </div>
            </div>

          </div>
        </div>

        {/* Bottom row */}
        <div style={{
          borderTop: "1px solid var(--border)",
          paddingTop: "var(--space-8)",
          display: "flex",
          flexDirection: "row",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "var(--space-4)",
          flexWrap: "wrap",
        }}>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--text-xs)",
            color: "var(--gray-700)",
          }}>
            © 2026 Bhavdeep Arora · MIT License
          </span>
        </div>

      </div>
    </footer>
  );
}