const STEPS = [
  {
    n: "01",
    title: "Request arrives",
    body: "Every HTTP request hitting your origin is intercepted by Thunderhead's reverse proxy before touching your app.",
  },
  {
    n: "02",
    title: "Signals are sampled",
    body: "The scorer reads five passive signals from the request — no JavaScript, no cookies, no challenges issued.",
  },
  {
    n: "03",
    title: "Score is computed",
    body: "Each signal contributes a weighted score. Signals stack additively up to a maximum of 100.",
  },
  {
    n: "04",
    title: "Action is dispatched",
    body: "Below 40: the request is forwarded silently. 40–74: response is delayed by 5 seconds. 75+: a 403 is returned immediately.",
  },
  {
    n: "05",
    title: "Everything is logged",
    body: "Every decision is emitted as structured JSON to stdout or a file — ready for your existing observability stack.",
  },
];

export default function HowItWorksSteps({ inView }: { inView: boolean }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
      {STEPS.map((step, i) => (
        <div
          key={step.n}
          style={{
            display: "flex",
            gap: 20,
            paddingBlock: 20,
            borderBottom: i < STEPS.length - 1 ? "1px solid var(--border)" : "none",
            opacity: inView ? 1 : 0,
            transform: inView ? "translateX(0)" : "translateX(-12px)",
            transition: `opacity 500ms ease ${i * 80}ms, transform 500ms cubic-bezier(0.16,1,0.3,1) ${i * 80}ms`,
          }}
        >
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            fontWeight: 500,
            letterSpacing: "0.06em",
            color: "var(--gray-700)",
            paddingTop: 2,
            flexShrink: 0,
            width: 24,
          }}>
            {step.n}
          </span>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <span style={{
              fontFamily: "var(--font-sans)",
              fontSize: 14,
              fontWeight: 600,
              letterSpacing: "-0.02em",
              color: "var(--white)",
            }}>
              {step.title}
            </span>
            <span style={{
              fontFamily: "var(--font-sans)",
              fontSize: 13,
              color: "var(--gray-500)",
              lineHeight: 1.6,
            }}>
              {step.body}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}