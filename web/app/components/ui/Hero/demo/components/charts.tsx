"use client";

import { useEffect, useState } from "react";
import type { Counts } from "../types";
import { COLOR } from "../theme";

// ─── Charts ────────────────────────────────────────────────────────────────────

export function Sparkbar({ data }: { data: number[] }) {
  const max = Math.max(...data, 1);
  return (
    <div className="flex items-end gap-0.5 h-11">
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

// Smooth area/line chart — a calmer alternative to Sparkbar for slower-moving data.
export function AreaSpark({ data, height = 44 }: { data: number[]; height?: number }) {
  const width = 280;
  const max = Math.max(...data, 1);
  const n = data.length;

  const points = data.map((v, i) => ({
    x: n > 1 ? (i / (n - 1)) * width : 0,
    y: height - (v / max) * (height - 4) - 2, // 2px padding top/bottom
  }));

  // Build a smooth cubic-bezier path through the points
  const linePath = points.reduce((acc, p, i) => {
    if (i === 0) return `M ${p.x},${p.y}`;
    const prev = points[i - 1];
    const cx = (prev.x + p.x) / 2;
    return `${acc} C ${cx},${prev.y} ${cx},${p.y} ${p.x},${p.y}`;
  }, "");

  const areaPath = `${linePath} L ${width},${height} L 0,${height} Z`;

  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} preserveAspectRatio="none">
      <defs>
        <linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#f4f4f5" stopOpacity="0.18" />
          <stop offset="100%" stopColor="#f4f4f5" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill="url(#areaFill)" />
      <path d={linePath} fill="none" stroke="#a1a1aa" strokeWidth={1.5} strokeLinecap="round" />
    </svg>
  );
}

export function DonutChart({ counts }: { counts: Counts }) {
  const size = 72, r = 26, cx = size / 2, cy = size / 2, circ = 2 * Math.PI * r;
  const total = Math.max(counts.total, 1);
  const ap = counts.allow / total, tp = counts.tarpit / total, bp = counts.block / total;
  return (
    <svg width={size} height={size} className="-rotate-90 shrink-0">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#3f3f46" strokeWidth={9} />
      {([
        { p: ap, color: COLOR.allow.text, offset: 0 },
        { p: tp, color: COLOR.tarpit.text, offset: ap },
        { p: bp, color: COLOR.block.text, offset: ap + tp },
      ] as const).map((seg, i) => (
        <circle
          key={i}
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke={seg.color}
          strokeWidth={9}
          strokeDasharray={`${seg.p * circ} ${circ}`}
          strokeDashoffset={-seg.offset * circ}
        />
      ))}
    </svg>
  );
}

export type TrafficBucket = { allow: number; tarpit: number; block: number };

export function TrafficChart({ data, height = 72 }: { data: TrafficBucket[]; height?: number }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return <div style={{ height }} />;

  const W = 280;
  const N = data.length;
  if (N < 2) return null;

  // shared max across all series so proportions are correct
  const globalMax = Math.max(...data.map(d => d.allow + d.tarpit + d.block), 1);

  const series: { key: keyof TrafficBucket; color: string }[] = [
    { key: "allow",  color: COLOR.allow.text  },
    { key: "tarpit", color: COLOR.tarpit.text },
    { key: "block",  color: COLOR.block.text  },
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
    <div className="flex flex-col gap-1.5">
      <svg viewBox={`0 0 ${W} ${height}`} width="100%" height={height} preserveAspectRatio="none">
        <defs>
          {series.map(({ key, color }) => (
            <linearGradient key={key} id={`tg-${key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%"   stopColor={color} stopOpacity={0.12} />
              <stop offset="100%" stopColor={color} stopOpacity={0}    />
            </linearGradient>
          ))}
        </defs>

        {gridYs.map((y, i) => (
          <line key={i} x1={0} y1={y} x2={W} y2={y} stroke="#27272a" strokeWidth={0.5} />
        ))}

        {/* draw allow first (tallest, at back), then tarpit, block on top */}
        {series.map(({ key, color }) => {
          const { line, area } = buildPath(data.map(d => d[key]));
          return (
            <g key={key}>
              <path d={area} fill={`url(#tg-${key})`} />
              <path d={line} fill="none" stroke={color} strokeWidth={1.5}
                    strokeLinecap="round" strokeLinejoin="round" />
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