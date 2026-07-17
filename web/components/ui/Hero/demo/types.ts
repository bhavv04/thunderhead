// ─── Types ─────────────────────────────────────────────────────────────────────

export type Action = "allow" | "tarpit" | "block";

export type Page =
  | "Overview"
  | "Live feed"
  | "Analytics"
  | "Thresholds"
  | "Allowlist"
  | "Signals"
  | "Logs"
  | "Settings";

export interface PoolEntry {
  ip: string;
  path: string;
  score: number;
  action: Action;
}

export interface LogEntry extends PoolEntry {
  timestamp: number;
  id: number;
  time: string;
  ts: number;
}

export interface Counts {
  total: number;
  allow: number;
  tarpit: number;
  block: number;
}