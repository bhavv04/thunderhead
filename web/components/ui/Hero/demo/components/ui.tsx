"use client";

import { useState, useEffect } from "react";
import type { Action } from "@/components/ui/Hero/demo/types";
import { COLOR } from "@/components/ui/Hero/demo/theme";

// ─── Reusable UI ───────────────────────────────────────────────────────────────

export function ActionBadge({ action }: { action: Action }) {
  const c = COLOR[action];
  return (
    <span
      className="inline-block text-[10px] font-medium px-[7px] py-px rounded tracking-wide"
      style={{ background: c.bg, color: c.text, border: `0.5px solid ${c.border}` }}
    >
      {action}
    </span>
  );
}

export function ScoreChip({ score, action }: { score: number; action: Action }) {
  return (
    <span className="inline-block text-[11px] min-w-[24px] text-right tabular-nums" style={{ color: COLOR[action].text }}>
      {score}
    </span>
  );
}

export function StatCard({ label, value, sub, valueColor }: {
  label: string; value: number | string; sub: string; valueColor?: string;
}) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const display = mounted
    ? (typeof value === "number" ? value.toLocaleString() : value)
    : (typeof value === "number" ? value : value);

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3">
      <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-1.5">{label}</div>
      <div
        className="text-[22px] font-medium leading-none tabular-nums"
        style={{ color: valueColor ?? "#f4f4f5" }}
        suppressHydrationWarning
      >
        {display}
      </div>
      <div className="text-[10px] text-zinc-500 mt-1.5" suppressHydrationWarning>{sub}</div>
    </div>
  );
}

export function Panel({ title, right, children, padBody = true }: {
  title: string; right?: React.ReactNode; children: React.ReactNode; padBody?: boolean;
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800">
        <span className="text-[11px] font-medium text-zinc-100">{title}</span>
        {right && <span className="text-[10px] text-zinc-500" suppressHydrationWarning>{right}</span>}
      </div>
      <div className={padBody ? "p-3.5" : ""}>{children}</div>
    </div>
  );
}

export function Input({ value, onChange, placeholder }: {
  value: string; onChange: (v: string) => void; placeholder?: string;
}) {
  return (
    <input
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      className="bg-zinc-800 border border-zinc-700 rounded-md px-3 py-1.5 text-[11px] text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-zinc-500 w-full"
    />
  );
}

export function Btn({ children, onClick, variant = "default", size = "sm" }: {
  children: React.ReactNode; onClick?: () => void; variant?: "default" | "danger" | "ghost"; size?: "sm" | "xs";
}) {
  const base = "inline-flex items-center gap-1 rounded cursor-pointer transition-colors";
  const sz = size === "xs" ? "px-2 py-0.5 text-xs" : "px-2.5 py-1 text-xs";
  const v = variant === "danger"
    ? "bg-stone-800  text-zinc-400 hover:bg-stone-700"
    : variant === "ghost"
    ? "bg-transparent text-zinc-400 hover:text-zinc-200 hover:border-zinc-500"
    : "bg-zinc-800 text-zinc-300 hover:bg-zinc-700";
  return <button onClick={onClick} className={`${base} ${sz} ${v}`}>{children}</button>;
}