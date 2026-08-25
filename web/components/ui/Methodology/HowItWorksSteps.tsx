const STEPS = [
  {
    n: "1",
    title: "Request arrives",
    body: "Every HTTP request hitting your origin is intercepted by Thunderhead's reverse proxy before touching your app.",
  },
  {
    n: "2",
    title: "Signals are sampled",
    body: "The scorer reads five passive signals from the request - no JavaScript, no cookies, no challenges issued.",
  },
  {
    n: "3",
    title: "Score is computed",
    body: "Each signal contributes a weighted score. Signals stack additively up to a maximum of 100.",
  },
  {
    n: "4",
    title: "Action is dispatched",
    body: "Below 40: the request is forwarded silently. 40–74: response is delayed by 5 seconds. 75+: a 403 is returned immediately.",
  },
  {
    n: "5",
    title: "Everything is logged",
    body: "Every decision is emitted as structured JSON to stdout or a file - ready for your existing observability stack.",
  },
];

export default function HowItWorksSteps({ inView }: { inView: boolean }) {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
      {STEPS.map((step, i) => (
        <div
          key={step.n}
          className="flex gap-4 py-4 duration-500"
          style={{
            opacity: inView ? 1 : 0,
            transform: inView ? "translateX(0)" : "translateX(-12px)",
            transitionDelay: `${i * 80}ms`,
            transitionTimingFunction: "cubic-bezier(0.16,1,0.3,1)",
          }}
        >
          <span className="text-sm font-medium text-white">
            {step.n}
          </span>
          <div className="flex flex-col gap-1">
            <span className="text-sm font-medium text-white">
              {step.title}
            </span>
            <span className="text-sm text-zinc-400 leading-relaxed">
              {step.body}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}