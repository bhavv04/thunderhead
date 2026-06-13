"use client";

import type { LogEntry, Counts } from "../types";
import { COLOR } from "../theme";
import { pct } from "../utils";
import { StatCard, Panel, Btn } from "../components/ui";
import { AreaSpark, DonutChart } from "../components/charts";
import { LogTable } from "../components/LogTable";
import type { Action } from "../types";

export function OverviewPage({ logs, counts, sparkData, rpsDisplay, latency, proxyUp, onExport, onRefresh }: {
  logs: LogEntry[]; counts: Counts; sparkData: number[]; rpsDisplay: number;
  latency: number; proxyUp: boolean; onExport: () => void; onRefresh: () => void;
}) {
  return (
    <div className="flex-1 overflow-y-auto p-3 sm:p-[14px_18px] flex flex-col gap-2.5">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        <StatCard label="Total requests" value={counts.total} sub={`${rpsDisplay} req/s`} />
        <StatCard label="Allowed"   value={counts.allow}  sub={pct(counts.allow, counts.total)}  valueColor={COLOR.allow.text}  />
        <StatCard label="Tarpitted" value={counts.tarpit} sub={pct(counts.tarpit, counts.total)} valueColor={COLOR.tarpit.text} />
        <StatCard label="Blocked"   value={counts.block}  sub={pct(counts.block, counts.total)}  valueColor={COLOR.block.text}  />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-[1.35fr_1fr] gap-2.5">
        <Panel title="Request volume" right="last 20 s"><AreaSpark data={sparkData} /></Panel>
        <Panel title="Action breakdown" right={`${counts.total} total`} padBody={false}>
          <div className="flex items-center gap-3.5 p-2.5">
            <DonutChart counts={counts} />
            <div className="flex flex-col gap-1.5 flex-1">
              {(["allow", "tarpit", "block"] as Action[]).map(a => (
                <div key={a} className="flex items-center gap-1.5 text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: COLOR[a].text }} />
                  <span className="text-zinc-400 flex-1 capitalize">{a}</span>
                  <span className="font-medium text-zinc-100">{pct(counts[a], counts.total)}</span>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
        <Panel title="Proxy health" padBody={false}>
          <div className="p-3.5 flex flex-col gap-2">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-400">Status</span>
              <span className={`font-medium flex items-center gap-1.5 ${proxyUp ? "text-green-400" : "text-red-400"}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${proxyUp ? "bg-green-400" : "bg-red-400"}`} />
                {proxyUp ? "Online" : "Offline"}
              </span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-400">Latency</span>
              <span className={`font-medium tabular-nums ${latency > 50 ? "text-yellow-400" : "text-zinc-100"}`}>{latency}ms</span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-400">Listen port</span>
              <span className="font-medium text-zinc-100">:8080</span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-400">Mode</span>
              <span className="font-medium text-zinc-100">Intercept</span>
            </div>
          </div>
        </Panel>

        <Panel title="Top blocked IPs" padBody={false}>
          <div className="p-3.5 flex flex-col gap-1.5">
            {Object.entries(
              logs.filter(l => l.action === "block").reduce<Record<string, number>>((acc, l) => ({ ...acc, [l.ip]: (acc[l.ip] ?? 0) + 1 }), {})
            ).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([ip, n]) => (
              <div key={ip} className="flex items-center gap-2 text-[11px]">
                <span className="text-zinc-400 flex-1 tabular-nums">{ip}</span>
                <div className="w-16 h-1 bg-zinc-800 rounded-full overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${Math.min((n / counts.block) * 100, 100)}%`, background: COLOR.block.text }} />
                </div>
                <span className="text-zinc-500 w-5 text-right">{n}</span>
              </div>
            ))}
            {logs.filter(l => l.action === "block").length === 0 && <div className="text-[11px] text-zinc-500">No blocked requests yet.</div>}
          </div>
        </Panel>
      </div>

      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden shrink-0">
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