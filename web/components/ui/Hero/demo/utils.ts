import type { LogEntry } from "./types";

// ─── Helpers ───────────────────────────────────────────────────────────────────

export function formatTime(timestamp: number): string {
  return new Date(timestamp).toISOString().slice(11, 19);
}

export function getTime(): string {
  return formatTime(Date.now());
}

export function pct(n: number, total: number): string {
  if (total === 0) return "-";
  return Math.round((n / total) * 100) + "%";
}

export function relTime(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  return `${Math.floor(s / 60)}m ago`;
}

export function downloadCSV(logs: LogEntry[]) {
  const header = "time,ip,path,score,action";
  const rows = logs.map(l => `${l.time},${l.ip},${l.path},${l.score},${l.action}`);
  const blob = new Blob([[header, ...rows].join("\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "thunderhead-logs.csv";
  a.click();
}