export default function PassiveVisual({ animate }: { animate: boolean }) {
  const signals = [
    { icon: "", label: "robots.txt check"       },
    { icon: "", label: "Path sequence tracking" },
    { icon: "",  label: "Rate window (60s)"      },
    { icon: "", label: "Header inspection"       },
    { icon: "", label: "Content-type analysis"  },
  ];

  const blocked = [
    { label: "JS challenge" },
    { label: "CAPTCHA"      },
    { label: "Cookies set"  },
    { label: "Fingerprint"  },
  ];

  return (
    <div className="flex flex-col gap-3">

      {/* Signals table */}
      <div className="overflow-hidden rounded-xl border border-white/10 bg-zinc-950 text-sm">
        <div className="border-b border-white/10 px-4 py-3 text-xs uppercase tracking-wide text-zinc-500">
          PASSIVE SIGNALS ONLY
        </div>
        {signals.map((s, i) => (
          <div
            key={i}
            className={[
              "flex items-center gap-2.5 px-4 py-2 transition-opacity duration-300",
              i < signals.length - 1 ? "border-b border-white/5" : "",
            ].join(" ")}
            style={{
              opacity: animate ? 1 : 0,
              transitionDelay: `${i * 50}ms`,
            }}
          >
            <span>{s.icon}</span>
            <span className="flex-1 text-zinc-300">{s.label}</span>
            <span className="rounded-full border border-green-500/20 bg-green-500/10 px-2 py-0.5 text-[10px] uppercase tracking-wide text-green-500">
              passive
            </span>
          </div>
        ))}
      </div>

      {/* Blocked methods grid */}
      <div className="grid grid-cols-2 gap-1.5">
        {blocked.map((b, i) => (
          <div
            key={i}
            className="flex items-center gap-1.5 rounded-lg border border-red-500/10 bg-red-500/5 px-3 py-2 text-xs text-zinc-500 transition-opacity duration-300"
            style={{
              opacity: animate ? 1 : 0,
              transitionDelay: `${300 + i * 50}ms`,
            }}
          >
            <span className="text-red-500/40 font-bold">✕</span>
            <span>{b.label}</span>
          </div>
        ))}
      </div>

    </div>
  );
}