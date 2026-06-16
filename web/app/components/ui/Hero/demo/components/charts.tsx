"use client";

import { useEffect, useState } from "react";
import type { Counts, LogEntry } from "../types";
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

export function ScoreHeatmap({ logs }: { logs: LogEntry[] }) {
  const buckets = Array.from({ length: 10 }, (_, i) => ({
    label: `${i * 10}`,
    count: logs.filter(l => l.score >= i * 10 && l.score < (i + 1) * 10).length,
    color: i < 4 ? COLOR.allow.text : i < 8 ? COLOR.tarpit.text : COLOR.block.text,
  }));
  const max = Math.max(...buckets.map(b => b.count), 1);

  if (logs.length === 0) {
    return <div className="text-[11px] text-zinc-500">Waiting for data…</div>;
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-end gap-1 h-20">
        {buckets.map((b) => (
          <div key={b.label} className="flex-1 flex flex-col items-center gap-1 h-full justify-end">
            <div
              className="w-full rounded-sm transition-all duration-300 relative group"
              style={{
                height: `${Math.max((b.count / max) * 100, b.count > 0 ? 4 : 0)}%`,
                background: b.color,
                opacity: 0.3 + (b.count / max) * 0.7,
              }}
            >
              {/* tooltip on hover */}
              {b.count > 0 && (
                <div className="absolute -top-6 left-1/2 -translate-x-1/2 bg-zinc-900 text-zinc-100 text-[9px] px-1.5 py-0.5 rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10">
                  {b.count}
                </div>
              )}
            </div>
            <span className="text-[9px] text-zinc-600">{b.label}</span>
          </div>
        ))}
      </div>

      {/* legend */}
      <div className="flex items-center gap-3 pt-1 border-t border-zinc-800">
        {([
          { label: "low (0–39)",    color: COLOR.allow.text  },
          { label: "mid (40–79)",   color: COLOR.tarpit.text },
          { label: "high (80–99)",  color: COLOR.block.text  },
        ] as const).map(({ label, color }) => (
          <span key={label} className="flex items-center gap-1 text-[10px] text-zinc-500">
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

export function ScoreScatter({ logs }: { logs: LogEntry[] }) {
  const [hovered, setHovered] = useState<LogEntry | null>(null);
  const W = 500, H = 100, X0 = 0, PAD = 4;

  if (logs.length === 0) {
    return <div className="text-xs text-zinc-500">Waiting for data…</div>;
  }

  const times = logs.map(l => l.timestamp ?? l.ts ?? 0);
  const minT = Math.min(...times);
  const maxT = Math.max(...times, minT + 1);

  const px = (l: LogEntry) => X0 + ((( l.timestamp ?? l.ts ?? 0) - minT) / (maxT - minT)) * W;
  const py = (l: LogEntry) => PAD + (1 - l.score / 100) * (H - PAD * 2);

  return (
    <div className="flex flex-col gap-2">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        height={H}
        style={{ overflow: "visible" }}
      >
        {/* score guide lines */}
        {[25, 50, 75].map(s => {
          const y = py({ score: s } as LogEntry);
          return (
            <g key={s}>
              <line x1={0} x2={W} y1={y} y2={y} stroke="#27272a" strokeWidth={0.5} strokeDasharray="3 2" />
              <text x={W + 4} y={y + 3} fontSize={8} fill="#52525b">{s}</text>
            </g>
          );
        })}

        {/* dots — render allow first so block/tarpit sit on top */}
        {(["allow", "tarpit", "block"] as const).map(action =>
          logs
            .filter(l => l.action === action)
            .map((l, i) => (
              <circle
                key={`${action}-${i}`}
                cx={px(l)}
                cy={py(l)}
                r={hovered === l ? 4 : 2.5}
                fill={COLOR[action].text}
                opacity={hovered && hovered !== l ? 0.25 : 0.75}
                style={{ cursor: "pointer", transition: "r 0.1s, opacity 0.1s" }}
                onMouseEnter={() => setHovered(l)}
                onMouseLeave={() => setHovered(null)}
              />
            ))
        )}

        {/* tooltip */}
        {hovered && (() => {
          const cx = px(hovered);
          const cy = py(hovered);
          const ttX = cx > W * 0.7 ? cx - 112 : cx + 8;
          const ttY = cy > H * 0.6 ? cy - 44 : cy + 6;
          return (
            <g pointerEvents="none">
              <rect x={ttX} y={ttY} width={104} height={38} rx={4} fill="#18181b" />
              <text x={ttX + 7} y={ttY + 13} fontSize={9} fill="#a1a1aa">{hovered.path ?? hovered.ip ?? "—"}</text>
              <text x={ttX + 7} y={ttY + 25} fontSize={10} fill={COLOR[hovered.action].text}>
                {hovered.action}
              </text>
              <text x={ttX + 7} y={ttY + 35} fontSize={9} fill="#71717a">score {hovered.score}</text>
            </g>
          );
        })()}
      </svg>

      <div className="flex items-center gap-3 pt-1 border-t border-zinc-800">
        {(["allow", "tarpit", "block"] as const).map(a => (
          <span key={a} className="flex items-center gap-1 text-[10px] text-zinc-500">
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: COLOR[a].text }} />
            {a}
          </span>
        ))}
        <span className="ml-auto text-[10px] text-zinc-600">{logs.length} events</span>
      </div>
    </div>
  );
}
