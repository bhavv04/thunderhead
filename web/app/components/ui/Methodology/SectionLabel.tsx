export default function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
      <div style={{ width: 3, height: 14, borderRadius: 2, background: "var(--accent)" }} />
      <span style={{
        fontFamily: "var(--font-mono)",
        fontSize: 10,
        letterSpacing: "0.12em",
        textTransform: "uppercase",
        color: "var(--gray-500)",
      }}>
        {children}
      </span>
    </div>
  );
}