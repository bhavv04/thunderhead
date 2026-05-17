export default function Diagram() {
    return (
        <div className="border-2 border-ink rounded-2xl overflow-hidden">
          {/* Diagram header */}
          <div className="bg-ink text-cream px-6 py-3 flex items-center gap-2 text-sm">
            <span className="w-3 h-3 rounded-full bg-danger"></span>
            <span className="w-3 h-3 rounded-full bg-warn"></span>
            <span className="w-3 h-3 rounded-full bg-signal"></span>
            <span className="ml-2 text-cream/40">thunderhead · live</span>
          </div>

          {/* Diagram body */}
          <div className="bg-ink/95 p-8 flex flex-col md:flex-row items-center justify-center gap-4">
            {/* Incoming */}
            <div className="flex flex-col gap-2">
              {["curl/7.88", "Googlebot", "python-requests", "Mozilla/5.0"].map((ua, i) => (
                <div key={i} className="bg-ink text-cream/70 text-xs px-3 py-1.5 rounded">
                  {ua}
                </div>
              ))}
            </div>

            {/* Arrow */}
            <div className="text-cream/30 text-2xl font-black rotate-90 md:rotate-0">→</div>

            {/* Thunderhead box */}
            <div className="bg-punch rounded-xl px-6 py-4 text-center">
              <div className="text-cream font-black text-lg">thunderhead</div>
              <div className="text-cream/60 text-xs mt-1">scoring engine</div>
            </div>

            {/* Arrow */}
            <div className="text-cream/30 text-2xl font-black rotate-90 md:rotate-0">→</div>

            {/* Outcomes */}
            <div className="flex flex-col gap-2">
              {[
                { label: "allow", score: "12", icon: "✓", style: "text-cream/70 bg-signal/60" },
                { label: "allow", score: "8", icon: "✓", style: "text-cream/70 bg-signal/60" },
                { label: "tarpit", score: "54", icon: "~", style: "text-cream/70 bg-warn/60" },
                { label: "block", score: "91", icon: "✗", style: "text-cream/70 bg-threat/60" },
              ].map((item, i) => (
                <div
                  key={i}
                  className={`bg-ink text-xs px-3 py-1.5 rounded flex justify-between gap-6 ${item.style}`}
                >
                  <span>{item.icon} {item.label}</span>
                  <span className="italic">score {item.score}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
    );
}