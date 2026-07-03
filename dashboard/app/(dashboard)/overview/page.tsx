"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "../../../lib/api";
import type { MetricsResponse, ClientsResponse, HealthResponse } from "../../../lib/types";
import { usePoll } from "../../../lib/hooks";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function pct(a: number, b: number) {
  if (b === 0) return "0%";
  return `${((a / b) * 100).toFixed(1)}%`;
}

function scoreColor(score: number) {
  if (score >= 75) return "#f87171";
  if (score >= 40) return "#fbbf24";
  return "#4ade80";
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color }: {
  label: string; value: string | number; sub: string; color?: string;
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3">
      <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-1.5">{label}</div>
      <div className="text-[22px] font-medium leading-none tabular-nums" style={{ color: color ?? "#f4f4f5" }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </div>
      <div className="text-[10px] text-zinc-500 mt-1.5">{sub}</div>
    </div>
  );
}

// ─── Traffic chart ────────────────────────────────────────────────────────────

type Bucket = { allow: number; tarpit: number; block: number };

function TrafficChart({ data, height = 80 }: { data: Bucket[]; height?: number }) {
  const W = 560;
  const N = data.length;
  if (N < 2) return <div style={{ height }} className="bg-zinc-800/30 rounded animate-pulse" />;

  const globalMax = Math.max(...data.map(d => d.allow + d.tarpit + d.block), 1);

  const series: { key: keyof Bucket; color: string }[] = [
    { key: "allow",  color: "#4ade80" },
    { key: "tarpit", color: "#fbbf24" },
    { key: "block",  color: "#f87171" },
  ];

  function buildPath(values: number[]) {
    const pts = values.map((v, i) => ({
      x: (i / (N - 1)) * W,
      y: height - 4 - (v / globalMax) * (height - 10),
    }));
    const line = pts.reduce((acc, p, i) => {
      if (i === 0) return `M ${p.x},${p.y}`;
      const prev = pts[i - 1];
      const cx = (prev.x + p.x) / 2;
      return `${acc} C ${cx},${prev.y} ${cx},${p.y} ${p.x},${p.y}`;
    }, "");
    return { line, area: `${line} L ${W},${height} L 0,${height} Z` };
  }

  const gridYs = [0.25, 0.5, 0.75].map(f => height - 4 - f * (height - 10));

  return (
    <div className="flex flex-col gap-2">
      <svg viewBox={`0 0 ${W} ${height}`} width="100%" height={height} preserveAspectRatio="none">
        <defs>
          {series.map(({ key, color }) => (
            <linearGradient key={key} id={`og-${key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%"   stopColor={color} stopOpacity={0.15} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        {gridYs.map((y, i) => (
          <line key={i} x1={0} y1={y} x2={W} y2={y} stroke="#27272a" strokeWidth={0.5} />
        ))}
        {series.map(({ key, color }) => {
          const { line, area } = buildPath(data.map(d => d[key]));
          return (
            <g key={key}>
              <path d={area} fill={`url(#og-${key})`} />
              <path d={line} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
            </g>
          );
        })}
      </svg>
      <div className="flex items-center gap-3">
        {series.map(({ key, color }) => (
          <span key={key} className="flex items-center gap-1 text-[10px] text-zinc-500">
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
            {key}
          </span>
        ))}
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function OverviewPage() {
  const [buckets, setBuckets] = useState<Bucket[]>(
    Array.from({ length: 60 }, () => ({ allow: 0, tarpit: 0, block: 0 }))
  );
  const prevMetrics = useState<MetricsResponse | null>(null);

  const fetchAll = useCallback(async () => {
    const [metrics, clients, health] = await Promise.all([
      api.metrics(),
      api.clients(),
      api.health(),
    ]);
    return { metrics, clients, health };
  }, []);

  const { data, error, loading } = usePoll(fetchAll, 5000);

  // roll traffic bucket every poll
  useEffect(() => {
    if (!data) return;
    const m = data.metrics;
    setBuckets(prev => [
      ...prev.slice(1),
      {
        allow:  m.allowed,
        tarpit: m.tarpit,
        block:  m.blocked,
      },
    ]);
  }, [data]);

  if (loading) return (
    <div className="flex-1 flex items-center justify-center text-zinc-500 text-sm">
      Loading...
    </div>
  );

  if (error) return (
    <div className="flex-1 flex items-center justify-center text-red-400 text-sm">
      {error}
    </div>
  );

  const { metrics, clients, health } = data!;
  const clientList = Object.entries(clients.clients).sort((a, b) => b[1].score - a[1].score);

  return (
    <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
      {/* Topbar */}
      <div className="flex items-center justify-between">
        <h1 className="text-[13px] font-medium text-zinc-100">Overview</h1>
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
          <span className="text-[11px] text-zinc-500">up {health.uptime}</span>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        <StatCard label="Total"     value={metrics.total}   sub="requests"                          />
        <StatCard label="Allowed"   value={metrics.allowed} sub={pct(metrics.allowed, metrics.total)}  color="#4ade80" />
        <StatCard label="Tarpitted" value={metrics.tarpit}  sub={pct(metrics.tarpit,  metrics.total)}  color="#fbbf24" />
        <StatCard label="Blocked"   value={metrics.blocked} sub={pct(metrics.blocked, metrics.total)}  color="#f87171" />
      </div>

      {/* Traffic chart */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800">
          <span className="text-[11px] font-medium text-zinc-100">Traffic</span>
          <span className="text-[10px] text-zinc-500">live · 5s poll</span>
        </div>
        <div className="p-3">
          <TrafficChart data={buckets} />
        </div>
      </div>

      {/* Client table */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800">
          <span className="text-[11px] font-medium text-zinc-100">Active clients</span>
          <span className="text-[10px] text-zinc-500">{clientList.length} tracked</span>
        </div>
        {clientList.length === 0 ? (
          <div className="px-3 py-6 text-[11px] text-zinc-500 text-center">
            No clients tracked yet — send some requests through the proxy.
          </div>
        ) : (
          <table className="w-full text-[11px] border-collapse">
            <thead>
              <tr>
                {["IP", "Score", "", "Requests", "Robots", "Action"].map(h => (
                  <th key={h} className="px-3 py-2 text-left text-[10px] font-medium text-zinc-500 uppercase tracking-wider border-b border-zinc-800 bg-zinc-900">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {clientList.map(([ip, cs]) => {
                const action = cs.score >= 75 ? "block" : cs.score >= 40 ? "tarpit" : "allow";
                const color  = scoreColor(cs.score);
                const filled = Math.round((cs.score / 100) * 10);
                return (
                  <tr key={ip} className="border-b border-zinc-800/60 hover:bg-zinc-800/30 transition-colors">
                    <td className="px-3 py-2 font-mono text-zinc-300">{ip}</td>
                    <td className="px-3 py-2 tabular-nums font-medium" style={{ color }}>{cs.score.toFixed(1)}</td>
                    <td className="px-3 py-2 w-24">
                      <div className="flex gap-px">
                        {Array.from({ length: 10 }, (_, i) => (
                          <div key={i} className="flex-1 h-1 rounded-sm"
                            style={{ background: i < filled ? color : "#27272a" }} />
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-2 tabular-nums text-zinc-400">{cs.request_count}</td>
                    <td className="px-3 py-2 text-zinc-400">{cs.robots_violated ? <span className="text-yellow-400">yes</span> : "no"}</td>
                    <td className="px-3 py-2">
                      <span className="text-[10px] px-2 py-0.5 rounded-full font-medium"
                        style={{
                          color: color,
                          background: `${color}18`,
                          border: `0.5px solid ${color}40`,
                        }}>
                        {action}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}