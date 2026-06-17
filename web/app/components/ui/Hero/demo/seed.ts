import type { LogEntry } from "./types";
import { formatTime } from "./utils";

const IPS = [
  "203.0.113.42", "198.51.100.7", "192.168.1.101",
  "10.0.0.55", "172.16.0.12", "203.0.113.99", "10.0.1.204",
];
const PATHS = [
  "/", "/about", "/pricing", "/blog", "/api/users", "/api/orders",
  "/api/search", "/admin", "/robots.txt", "/sitemap.xml",
  "/api/login", "/api/checkout", "/api/products", "/api/admin/users", "/contact",
];

const SEED_BASE_TS = Date.UTC(2026, 5, 16, 12, 0, 0);

function makeEntry(id: number, offsetMs: number): LogEntry {
  const ip = IPS[id % IPS.length];
  const path = PATHS[id % PATHS.length];
  const score =
    ip === "203.0.113.42" ? 85 + (id % 10) :
    ip === "198.51.100.7" ? 55 + (id % 15) :
    10 + (id % 25);
  const action =
    score >= 75 ? "block" :
    score >= 40 ? "tarpit" : "allow";
  const ts = SEED_BASE_TS - offsetMs;
  return { id, ip, path, score, action, time: formatTime(ts), ts };
}

export const SEED_LOGS: LogEntry[] = Array.from({ length: 48 }, (_, i) =>
  makeEntry(i + 1, (48 - i) * 4000)  // one every ~4s going back 3 mins
);

export const SEED_COUNTS = {
  total:  47_832,
  allow:  Math.round(47_832 * 0.941),
  tarpit: Math.round(47_832 * 0.043),
  block:  Math.round(47_832 * 0.016),
};

export const SEED_TRAFFIC: { allow: number; tarpit: number; block: number }[] =
  Array.from({ length: 60 }, (_, i) => ({
    allow:  Math.round(4 + Math.sin(i * 0.3) * 2 + (i % 7 === 0 ? 4 : 0)),
    tarpit: i % 5 === 0 ? 1 : 0,
    block:  i % 13 === 0 ? 1 : 0,
  }));