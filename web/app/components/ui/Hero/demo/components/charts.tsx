"use client";

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