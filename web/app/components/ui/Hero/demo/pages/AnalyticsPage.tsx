"use client";

import { useEffect, useState } from "react";
import type { LogEntry, Counts } from "../types";
import { COLOR } from "../theme";
import { StatCard, Panel } from "../components/ui";
import { AreaSpark, TrafficChart } from "../components/charts";
import type { TrafficBucket } from "../components/charts";
import { pct } from "../utils";

export function AnalyticsPage({
  logs,
  counts,
  sparkData,
  trafficBuckets,
}: {
  logs: LogEntry[];
  counts: Counts;
  sparkData: number[];
  trafficBuckets: TrafficBucket[];
}) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  const allowPct = mounted ? pct(counts.allow, counts.total) : "—";
  const tarpitPct = mounted ? pct(counts.tarpit, counts.total) : "—";
  const blockPct = mounted ? pct(counts.block, counts.total) : "—";

  // Top paths
  const pathCounts = logs.reduce<Record<string, number>>((acc, l) => ({ ...acc, [l.path]: (acc[l.path] ?? 0) + 1 }), {});
  const topPaths = Object.entries(pathCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const maxPath = topPaths[0]?.[1] ?? 1;

  // Top IPs
  const ipCounts = logs.reduce<Record<string, number>>((acc, l) => ({ ...acc, [l.ip]: (acc[l.ip] ?? 0) + 1 }), {});
  const topIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const maxIP = topIPs[0]?.[1] ?? 1;

  // Score distribution buckets 0-9, 10-19, ... 90-99
  const scoreBuckets = Array.from({ length: 10 }, (_, i) => ({
    label: `${i * 10}–${i * 10 + 9}`,
    count: logs.filter(l => l.score >= i * 10 && l.score < (i + 1) * 10).length,
  }));
  const maxBucket = Math.max(...scoreBuckets.map(b => b.count), 1);

  return (
    <div className="flex-1 overflow-y-auto p-3 sm:p-[14px_18px] flex flex-col gap-2.5">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        <StatCard label="Total requests" value={counts.total} sub="all time" />
        <StatCard label="Allowed"   value={counts.allow}  sub={allowPct}  valueColor={COLOR.allow.text}  />
        <StatCard label="Tarpitted" value={counts.tarpit} sub={tarpitPct} valueColor={COLOR.tarpit.text} />
        <StatCard label="Blocked"   value={counts.block}  sub={blockPct}  valueColor={COLOR.block.text}  />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-[1.35fr_1fr] gap-2.5">
        <Panel title="Request trend" right="last 20 s">
          <AreaSpark data={sparkData} />
        </Panel>

        <Panel title="Request volume" right="last 60 s">
          <TrafficChart data={trafficBuckets} />
        </Panel>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
        <Panel title="Top paths by request volume">
          <div className="flex flex-col gap-2">
            {topPaths.length === 0 && <div className="text-[11px] text-zinc-500">Waiting for data…</div>}
            {topPaths.map(([path, n]) => (
              <div key={path} className="flex items-center gap-2 text-[11px]">
                <span className="text-zinc-100 w-32 truncate font-mono text-[10px]">{path}</span>
                <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-zinc-400" style={{ width: `${(n / maxPath) * 100}%` }} />
                </div>
                <span className="text-zinc-500 w-6 text-right tabular-nums">{n}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Top IPs by request volume">
          <div className="flex flex-col gap-2">
            {topIPs.length === 0 && <div className="text-[11px] text-zinc-500">Waiting for data…</div>}
            {topIPs.map(([ip, n]) => {
              const action = logs.find(l => l.ip === ip)?.action ?? "allow";
              return (
                <div key={ip} className="flex items-center gap-2 text-[11px]">
                  <span className="text-zinc-400 w-32 tabular-nums text-[10px]">{ip}</span>
                  <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${(n / maxIP) * 100}%`, background: COLOR[action].text }} />
                  </div>
                  <span className="text-zinc-500 w-6 text-right tabular-nums">{n}</span>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      <Panel title="Intent score distribution" right="0 – 100">
        <div className="flex items-end gap-1 h-24">
          {scoreBuckets.map((b, i) => {
            const pctH = Math.max((b.count / maxBucket) * 100, b.count > 0 ? 4 : 0);
            const col = i < 4 ? COLOR.allow.text : i < 8 ? COLOR.tarpit.text : COLOR.block.text;
            return (
              <div key={b.label} className="flex-1 flex flex-col items-center gap-1">
                <div className="w-full rounded-sm transition-all duration-300" style={{ height: `${pctH}%`, background: col, minHeight: b.count > 0 ? 3 : 0 }} />
                <span className="text-[8px] text-zinc-600 rotate-0">{i * 10}</span>
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}