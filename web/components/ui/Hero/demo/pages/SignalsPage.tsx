"use client";

import { useState } from "react";
import { COLOR } from "@/components/ui/Hero/demo/theme";
import { Panel } from "@/components/ui/Hero/demo/components/ui";

export function SignalsPage() {
  const [signals, setSignals] = useState([
    { id: 1, name: "Path is sensitive",        desc: "Matches /admin, /secret, /private, etc.", weight: 40, enabled: true  },
    { id: 2, name: "High request rate",         desc: "More than 10 req/s from a single IP.",   weight: 30, enabled: true  },
    { id: 3, name: "Known scanner UA",          desc: "User-agent matches scanner signatures.",  weight: 25, enabled: true  },
    { id: 4, name: "Geo: high-risk ASN",        desc: "IP belongs to a flagged network range.",  weight: 20, enabled: false },
    { id: 5, name: "No referer on deep path",   desc: "Direct hit on a non-root path.",         weight: 10, enabled: true  },
    { id: 6, name: "Payload anomaly",           desc: "Body or query string contains suspicious patterns.", weight: 15, enabled: false },
  ]);

  const toggle = (id: number) => setSignals(p => p.map(s => s.id === id ? { ...s, enabled: !s.enabled } : s));
  const setWeight = (id: number, w: number) => setSignals(p => p.map(s => s.id === id ? { ...s, weight: w } : s));

  return (
    <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-3">
      <Panel title="Scoring signals" right="max score 100">
        <div className="flex flex-col divide-y divide-zinc-800">
          {signals.map(s => (
            <div key={s.id} className="py-3 flex flex-col gap-2">
              <div className="flex items-start gap-3">
                <button
                  onClick={() => toggle(s.id)}
                  className={`mt-0.5 w-8 h-4 rounded-full transition-colors cursor-pointer shrink-0 relative ${s.enabled ? "bg-zinc-100" : "bg-zinc-700"}`}
                >
                  <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-zinc-900 transition-all ${s.enabled ? "left-4" : "left-0.5"}`} />
                </button>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className={`text-[12px] font-medium ${s.enabled ? "text-zinc-100" : "text-zinc-500"}`}>{s.name}</span>
                    <span className="text-[11px] tabular-nums" style={{ color: s.enabled ? COLOR.tarpit.text : "#52525b" }}>+{s.weight}</span>
                  </div>
                  <p className="text-[10px] text-zinc-500 mt-0.5">{s.desc}</p>
                  {s.enabled && (
                    <input
                      type="range" min={1} max={50} value={s.weight}
                      onChange={e => setWeight(s.id, +e.target.value)}
                      className="w-full mt-1.5 accent-yellow-400 cursor-pointer"
                    />
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}