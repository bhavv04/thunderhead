export default function TarpitVisual({ animate }: { animate: boolean }) {
  return (
    <div className="flex flex-col gap-3 text-sm">

      {/* Normal */}
      <div className="flex flex-col gap-1.5">
        <div className="flex justify-between text-xs uppercase tracking-wide text-zinc-500">
          <span>NORMAL REQUEST</span>
          <span className="text-green-500">~12ms</span>
        </div>
        <div className="h-5 overflow-hidden rounded-md border border-white/10 bg-white/5">
          <div
            className="h-full rounded-md opacity-70 transition-[width] duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] delay-100"
            style={{ width: animate ? "8%" : "0%", background: "var(--green)" }}
          />
        </div>
      </div>

      {/* Tarpitted */}
      <div className="flex flex-col gap-1.5">
        <div className="flex justify-between text-xs uppercase tracking-wide text-zinc-500">
          <span>TARPITTED REQUEST</span>
          <span className="text-amber-500">5000ms</span>
        </div>
        <div className="relative h-5 overflow-hidden rounded-md border border-white/10 bg-white/5">
          {/* Stripe fill */}
          <div
            className="absolute inset-y-0 left-0 rounded-md transition-[width] duration-700 ease-[cubic-bezier(0.16,1,0.3,1)] delay-200"
            style={{
              width: animate ? "92%" : "0%",
              background: "repeating-linear-gradient(90deg, rgba(245,158,11,0.08) 0px, rgba(245,158,11,0.08) 8px, transparent 8px, transparent 16px)",
            }}
          />
          {/* Solid leading edge */}
          <div
            className="absolute inset-y-0 left-0 rounded-md opacity-60 transition-[width] duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] delay-[900ms]"
            style={{ width: animate ? "8%" : "0%", background: "var(--amber)" }}
          />
          {/* Label */}
          {animate && (
            <div
              className="absolute inset-0 flex items-center pl-2 transition-opacity duration-300 delay-500"
              style={{ opacity: animate ? 1 : 0 }}
            >
              <span className="text-xs text-amber-500/60">⏱ 5s artificial delay</span>
            </div>
          )}
        </div>
      </div>

      {/* Blocked */}
      <div className="flex flex-col gap-1.5">
        <div className="flex justify-between text-xs uppercase tracking-wide text-zinc-500">
          <span>BLOCKED REQUEST</span>
          <span className="text-red-500">403</span>
        </div>
        <div
          className="flex h-5 items-center rounded-md border border-white/10 pl-2 transition-[background,border-color] duration-300 delay-300"
          style={{
            background: animate ? "var(--red-dim)" : "rgba(255,255,255,0.05)",
            borderWidth: 1, borderStyle: "solid", borderColor: animate ? "rgba(239,68,68,0.25)" : "rgba(255,255,255,0.06)",
          }}
        >
          <span
            className="text-xs transition-[color] duration-300 delay-500"
            style={{ color: animate ? "var(--red)" : "transparent" }}
          >
            403 Forbidden
          </span>
        </div>
      </div>

    </div>
  );
}