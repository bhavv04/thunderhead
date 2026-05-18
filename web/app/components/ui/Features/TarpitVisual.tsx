export default function TarpitVisual({ animate }: { animate: boolean }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10, fontFamily: "var(--font-mono)", fontSize: 11 }}>
      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        <div style={{ display: "flex", justifyContent: "space-between", color: "var(--gray-600)", fontSize: 9, letterSpacing: "0.06em" }}>
          <span>NORMAL REQUEST</span>
          <span style={{ color: "var(--green)" }}>~12ms</span>
        </div>
        <div style={{ height: 22, background: "rgba(255,255,255,0.03)", borderRadius: 5, overflow: "hidden", border: "1px solid rgba(255,255,255,0.06)" }}>
          <div style={{
            height: "100%",
            width: animate ? "8%" : "0%",
            background: "var(--green)",
            borderRadius: 5,
            opacity: 0.7,
            transition: "width 400ms cubic-bezier(0.16,1,0.3,1) 100ms",
          }} />
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        <div style={{ display: "flex", justifyContent: "space-between", color: "var(--gray-600)", fontSize: 9, letterSpacing: "0.06em" }}>
          <span>TARPITTED REQUEST</span>
          <span style={{ color: "var(--amber)" }}>5000ms</span>
        </div>
        <div style={{ height: 22, background: "rgba(255,255,255,0.03)", borderRadius: 5, overflow: "hidden", border: "1px solid rgba(255,255,255,0.06)", position: "relative" }}>
          <div style={{
            position: "absolute", left: 0, top: 0, height: "100%",
            width: animate ? "92%" : "0%",
            background: "repeating-linear-gradient(90deg, rgba(245,158,11,0.08) 0px, rgba(245,158,11,0.08) 8px, transparent 8px, transparent 16px)",
            borderRadius: 5,
            transition: "width 900ms cubic-bezier(0.16,1,0.3,1) 200ms",
          }} />
          <div style={{
            position: "absolute", left: 0, top: 0, height: "100%",
            width: animate ? "8%" : "0%",
            background: "var(--amber)",
            borderRadius: 5, opacity: 0.6,
            transition: "width 700ms cubic-bezier(0.16,1,0.3,1) 1100ms",
          }} />
          {animate && (
            <div style={{
              position: "absolute", inset: 0,
              display: "flex", alignItems: "center", paddingLeft: 8,
              opacity: animate ? 1 : 0,
              transition: "opacity 400ms ease 600ms",
            }}>
              <span style={{ fontSize: 9, color: "rgba(245,158,11,0.6)", letterSpacing: "0.04em" }}>⏱ 5s artificial delay</span>
            </div>
          )}
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        <div style={{ display: "flex", justifyContent: "space-between", color: "var(--gray-600)", fontSize: 9, letterSpacing: "0.06em" }}>
          <span>BLOCKED REQUEST</span>
          <span style={{ color: "var(--red)" }}>403</span>
        </div>
        <div style={{
          height: 22,
          background: animate ? "var(--red-dim)" : "rgba(255,255,255,0.03)",
          borderRadius: 5,
          border: "1px solid",
          borderColor: animate ? "rgba(239,68,68,0.25)" : "rgba(255,255,255,0.06)",
          display: "flex", alignItems: "center", paddingLeft: 8,
          transition: "background 300ms ease 400ms, border-color 300ms ease 400ms",
        }}>
          <span style={{
            fontSize: 9,
            color: animate ? "var(--red)" : "transparent",
            fontFamily: "var(--font-mono)",
            transition: "color 300ms ease 500ms",
            letterSpacing: "0.04em",
          }}>
            403 Forbidden
          </span>
        </div>
      </div>
    </div>
  );
}