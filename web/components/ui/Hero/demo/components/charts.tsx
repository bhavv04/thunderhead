"use client";

import { useEffect, useState } from "react";
import type { Counts, LogEntry } from "@/components/ui/Hero/demo/types";
import { COLOR } from "@/components/ui/Hero/demo/theme";

// ─── Shared bits ─────────────────────────────────────────────────────────

/** Small colored dot + label, used in every chart legend below. */
function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1 text-xs text-zinc-500">
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: color }} />
      {label}
    </span>
  );
}

const ACTION_LEGEND = [
  { key: "allow", color: COLOR.allow.text },
  { key: "tarpit", color: COLOR.tarpit.text },
  { key: "block", color: COLOR.block.text },
] as const;

// ─── Charts ──────────────────────────────────────────────────────────────

export function Sparkbar({ data }: { data: number[] }) {
  const max = Math.max(...data, 1);
  return (
    <div className="flex items-end gap-1 h-11">
      {data.map((v, i) => (
        <div
          key={i}
          className="flex-1 rounded-sm transition-all duration-200"
          style={{ height: `${Math.max((v / max) * 100, 3)}%`, background: i === data.length - 1 ? "#f4f4f5" : "#3f3f46" }}
        />
      ))}
    </div>
  );
}

export function DonutChart({ counts }: { counts: Counts }) {
  const size = 72, radius = 26, center = size / 2, circumference = 2 * Math.PI * radius;
  const total = Math.max(counts.total, 1);

  const segments = [
    { pct: counts.allow / total, color: COLOR.allow.text },
    { pct: counts.tarpit / total, color: COLOR.tarpit.text },
    { pct: counts.block / total, color: COLOR.block.text },
  ];

  // running offset so each segment starts where the previous one ended
  let offset = 0;

  return (
    <svg width={size} height={size} className="-rotate-90 shrink-0">
      <circle cx={center} cy={center} r={radius} fill="none" stroke="#3f3f46" strokeWidth={9} />
      {segments.map((seg, i) => {
        const circle = (
          <circle
            key={i}
            cx={center} cy={center} r={radius}
            fill="none"
            stroke={seg.color}
            strokeWidth={9}
            strokeDasharray={`${seg.pct * circumference} ${circumference}`}
            strokeDashoffset={-offset * circumference}
          />
        );
        offset += seg.pct;
        return circle;
      })}
    </svg>
  );
}

export type TrafficBucket = { allow: number; tarpit: number; block: number };

export function TrafficChart({ data, height = 72 }: { data: TrafficBucket[]; height?: number }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return <div style={{ height }} />;

  const width = 280;
  const pointCount = data.length;
  if (pointCount < 2) return null;

  // shared max across all series so proportions are correct
  const globalMax = Math.max(...data.map(d => d.allow + d.tarpit + d.block), 1);

  const series: { key: keyof TrafficBucket; color: string }[] = [
    { key: "allow", color: COLOR.allow.text },
    { key: "tarpit", color: COLOR.tarpit.text },
    { key: "block", color: COLOR.block.text },
  ];

  function buildPath(values: number[]) {
    const points = values.map((v, i) => ({
      x: (i / (pointCount - 1)) * width,
      y: height - 4 - (v / globalMax) * (height - 10),
    }));

    const line = points.reduce((acc, p, i) => {
      if (i === 0) return `M ${p.x},${p.y}`;
      const prev = points[i - 1];
      const midX = (prev.x + p.x) / 2;
      return `${acc} C ${midX},${prev.y} ${midX},${p.y} ${p.x},${p.y}`;
    }, "");

    return { line, area: `${line} L ${width},${height} L 0,${height} Z` };
  }

  const gridLineYs = [0.25, 0.5, 0.75].map(f => height - 4 - f * (height - 10));

  return (
    <div className="flex flex-col gap-2">
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} preserveAspectRatio="none">
        <defs>
          {series.map(({ key, color }) => (
            <linearGradient key={key} id={`tg-${key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.12} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>

        {gridLineYs.map((y, i) => (
          <line key={i} x1={0} y1={y} x2={width} y2={y} stroke="#27272a" strokeWidth={0.5} />
        ))}

        {/* draw allow first (tallest, at back), then tarpit, block on top */}
        {series.map(({ key, color }) => {
          const { line, area } = buildPath(data.map(d => d[key]));
          return (
            <g key={key}>
              <path d={area} fill={`url(#tg-${key})`} />
              <path d={line} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
            </g>
          );
        })}
      </svg>

      <div className="flex items-center gap-3">
        {series.map(({ key, color }) => (
          <LegendItem key={key} color={color} label={key} />
        ))}
      </div>
    </div>
  );
}

export function ScoreHeatmap({ logs }: { logs: LogEntry[] }) {
  const buckets = Array.from({ length: 10 }, (_, i) => ({
    label: `${i * 10}`,
    count: logs.filter(l => l.score >= i * 10 && l.score < (i + 1) * 10).length,
    color: i < 4 ? COLOR.allow.text : i < 8 ? COLOR.tarpit.text : COLOR.block.text,
  }));
  const max = Math.max(...buckets.map(b => b.count), 1);

  if (logs.length === 0) {
    return <div className="text-xs text-zinc-500">Waiting for data…</div>;
  }

  const legend = [
    { label: "low (0–39)", color: COLOR.allow.text },
    { label: "mid (40–79)", color: COLOR.tarpit.text },
    { label: "high (80–99)", color: COLOR.block.text },
  ];

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-end gap-1 h-20">
        {buckets.map(bucket => (
          <div key={bucket.label} className="flex-1 flex flex-col items-center gap-1 h-full justify-end">
            <div
              className="w-full rounded-sm transition-all duration-300 relative group"
              style={{
                height: `${Math.max((bucket.count / max) * 100, bucket.count > 0 ? 4 : 0)}%`,
                background: bucket.color,
                opacity: 0.3 + (bucket.count / max) * 0.7,
              }}
            >
              {/* tooltip on hover */}
              {bucket.count > 0 && (
                <div className="absolute -top-6 left-1/2 -translate-x-1/2 text-white text-xxs px-2 py-1 rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10">
                  {bucket.count}
                </div>
              )}
            </div>
            <span className="text-xxs text-zinc-600">{bucket.label}</span>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-3 pt-1 border-t border-zinc-800">
        {legend.map(({ label, color }) => (
          <LegendItem key={label} color={color} label={label} />
        ))}
      </div>
    </div>
  );
}

export function ScoreScatter({ logs }: { logs: LogEntry[] }) {
  const [hovered, setHovered] = useState<LogEntry | null>(null);
  const width = 500, height = 100, pad = 4;

  if (logs.length === 0) {
    return <div className="text-xs text-zinc-500">Waiting for data…</div>;
  }

  const times = logs.map(l => l.timestamp ?? l.ts ?? 0);
  const minTime = Math.min(...times);
  const maxTime = Math.max(...times, minTime + 1);

  const toX = (l: LogEntry) => (((l.timestamp ?? l.ts ?? 0) - minTime) / (maxTime - minTime)) * width;
  const toY = (l: LogEntry) => pad + (1 - l.score / 100) * (height - pad * 2);

  return (
    <div className="flex flex-col gap-2">
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} style={{ overflow: "visible" }}>
        {/* score guide lines */}
        {[25, 50, 75].map(score => {
          const y = toY({ score } as LogEntry);
          return (
            <g key={score}>
              <line x1={0} x2={width} y1={y} y2={y} stroke="#27272a" strokeWidth={0.5} strokeDasharray="3 2" />
              <text x={width + 4} y={y + 3} fontSize={8} fill="#52525b">{score}</text>
            </g>
          );
        })}

        {/* dots — render allow first so block/tarpit sit on top */}
        {ACTION_LEGEND.map(({ key: action, color }) =>
          logs
            .filter(l => l.action === action)
            .map((l, i) => (
              <circle
                key={`${action}-${i}`}
                cx={toX(l)}
                cy={toY(l)}
                r={hovered === l ? 4 : 2.5}
                fill={color}
                opacity={hovered && hovered !== l ? 0.25 : 0.75}
                style={{ cursor: "pointer", transition: "r 0.1s, opacity 0.1s" }}
                onMouseEnter={() => setHovered(l)}
                onMouseLeave={() => setHovered(null)}
              />
            ))
        )}

        {/* tooltip */}
        {hovered && (() => {
          const cx = toX(hovered);
          const cy = toY(hovered);
          const ttX = cx > width * 0.7 ? cx - 112 : cx + 8;
          const ttY = cy > height * 0.6 ? cy - 44 : cy + 6;
          return (
            <g pointerEvents="none">
              <rect x={ttX} y={ttY} width={104} height={38} rx={4} fill="#18181b" />
              <text x={ttX + 7} y={ttY + 13} fontSize={9} fill="#a1a1aa">{hovered.path ?? hovered.ip ?? "—"}</text>
              <text x={ttX + 7} y={ttY + 25} fontSize={10} fill={COLOR[hovered.action].text}>{hovered.action}</text>
              <text x={ttX + 7} y={ttY + 35} fontSize={9} fill="#71717a">score {hovered.score}</text>
            </g>
          );
        })()}
      </svg>

      <div className="flex items-center gap-3 pt-1 border-t border-zinc-800">
        {ACTION_LEGEND.map(({ key, color }) => (
          <LegendItem key={key} color={color} label={key} />
        ))}
        <span className="ml-auto text-xs text-zinc-600">{logs.length} events</span>
      </div>
    </div>
  );
}