"use client";

import { useEffect, useState } from "react";
import type { LogEntry, Counts, Action } from "@/components/ui/Hero/demo/types";
import { COLOR } from "@/components/ui/Hero/demo/theme";
import { pct } from "@/components/ui/Hero/demo/utils";
import { StatCard, Panel, Btn } from "@/components/ui/Hero/demo/components/ui";
import { DonutChart, TrafficChart } from "@/components/ui/Hero/demo/components/charts";
import type { TrafficBucket } from "@/components/ui/Hero/demo/components/charts";
import { LogTable } from "@/components/ui/Hero/demo/components/LogTable";

// ─── Small helpers ──────────────────────────────────────────────────────

/** One label/value row, used in the "Proxy health" panel. */
function StatRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-zinc-400">{label}</span>
      {children}
    </div>
  );
}

const ACTIONS: Action[] = ["allow", "tarpit", "block"];

// ─── Overview page ──────────────────────────────────────────────────────

export function OverviewPage({ logs, counts, sparkData, trafficBuckets, rpsDisplay, latency, proxyUp, onExport, onRefresh }: {
  logs: LogEntry[]; counts: Counts; sparkData: number[]; trafficBuckets: TrafficBucket[];
  rpsDisplay: number; latency: number; proxyUp: boolean; onExport: () => void; onRefresh: () => void;
}) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const percentOf = (n: number) => (mounted ? pct(n, counts.total) : "—");

  const blockedLogs = logs.filter(l => l.action === "block");
  const topBlockedIps = Object.entries(
    blockedLogs.reduce<Record<string, number>>((acc, l) => ({ ...acc, [l.ip]: (acc[l.ip] ?? 0) + 1 }), {})
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);

  return (
    <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-2">
      {/* Top stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        <StatCard label="Total requests" value={counts.total.toLocaleString()} sub={`${rpsDisplay} req/s`} />
        <StatCard label="Allowed" value={counts.allow.toLocaleString()} sub={percentOf(counts.allow)} valueColor={COLOR.allow.text} />
        <StatCard label="Tarpitted" value={counts.tarpit.toLocaleString()} sub={percentOf(counts.tarpit)} valueColor={COLOR.tarpit.text} />
        <StatCard label="Blocked" value={counts.block.toLocaleString()} sub={percentOf(counts.block)} valueColor={COLOR.block.text} />
      </div>

      {/* Traffic chart + action breakdown */}
      <div className="grid grid-cols-1 sm:grid-cols-[1.35fr_1fr] gap-3">
        <Panel title="Request volume" right="last 60 s">
          <TrafficChart data={trafficBuckets} />
        </Panel>

        <Panel title="Action breakdown" right={`${counts.total} total`} padBody={false}>
          <div className="flex items-center gap-4 p-3">
            <DonutChart counts={counts} />
            <div className="flex flex-col gap-2 flex-1">
              {ACTIONS.map(action => (
                <div key={action} className="flex items-center gap-2 text-xs">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: COLOR[action].text }} />
                  <span className="text-zinc-400 flex-1 capitalize">{action}</span>
                  <span className="font-medium text-zinc-100">{percentOf(counts[action])}</span>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </div>

      {/* Proxy health + top blocked IPs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Panel title="Proxy health" padBody={false}>
          <div className="p-4 flex flex-col gap-2">
            <StatRow label="Status">
              <span className={`font-medium flex items-center gap-2 ${proxyUp ? "text-green-400" : "text-red-400"}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${proxyUp ? "bg-green-400" : "bg-red-400"}`} />
                {proxyUp ? "Online" : "Offline"}
              </span>
            </StatRow>
            <StatRow label="Latency">
              <span className={`font-medium tabular-nums ${latency > 50 ? "text-yellow-400" : "text-zinc-100"}`}>{latency}ms</span>
            </StatRow>
            <StatRow label="Listen port">
              <span className="font-medium text-zinc-100">thunderhead.app</span>
            </StatRow>
            <StatRow label="Mode">
              <span className="font-medium text-zinc-100">Intercept</span>
            </StatRow>
          </div>
        </Panel>

        <Panel title="Top blocked IPs" padBody={false}>
          <div className="p-4 flex flex-col gap-2">
            {topBlockedIps.length === 0 ? (
              <div className="text-xs text-zinc-500">No blocked requests yet.</div>
            ) : (
              topBlockedIps.map(([ip, count]) => (
                <div key={ip} className="flex items-center gap-2 text-xs">
                  <span className="text-zinc-400 flex-1 tabular-nums">{ip}</span>
                  <div className="w-16 h-1 bg-zinc-800 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${Math.min((count / counts.block) * 100, 100)}%`, background: COLOR.block.text }}
                    />
                  </div>
                  <span className="text-zinc-500 w-5 text-right">{count}</span>
                </div>
              ))
            )}
          </div>
        </Panel>
      </div>

      {/* Live log */}
      <div className="rounded-lg overflow-hidden shrink-0">
        <div className="flex items-center justify-between px-3 py-2">
          <span className="font-medium text-zinc-100 text-xs">Live request log</span>
          <div className="flex items-center gap-2">
            <span className="text-xs">{logs.length} entries</span>
            <Btn size="xs" onClick={onExport}>Export</Btn>
            <Btn size="xs" variant="ghost" onClick={onRefresh}>Clear</Btn>
          </div>
        </div>
        <LogTable logs={logs.slice(-20)} flash />
      </div>
    </div>
  );
}