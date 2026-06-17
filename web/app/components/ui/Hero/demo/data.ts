import type { Action, LogEntry, Page } from "./types";

// ─── Nav ───────────────────────────────────────────────────────────────────────

export const NAV: { section: string; items: { label: Page; icon: string }[] }[] = [
  {
    section: "Dashboard",
    items: [
      { label: "Overview", icon: "layout-dashboard" },
      { label: "Live feed", icon: "activity" },
      { label: "Analytics", icon: "chart-line" },
    ],
  },
  {
    section: "Policy",
    items: [
      { label: "Thresholds", icon: "sliders-horizontal" },
      { label: "Allowlist", icon: "shield-check" },
      { label: "Signals", icon: "radar" },
    ],
  },
  {
    section: "System",
    items: [
      { label: "Logs", icon: "file-text" },
      { label: "Settings", icon: "settings" },
    ],
  },
];

// ─── Data generation ───────────────────────────────────────────────────────────

export const PATHS = [
  "/admin", "/login", "/api/v1/users", "/api/v2/data", "/private", "/internal", "/secret",
  "/robots.txt", "/", "/about", "/blog", "/contact", "/dashboard", "/wp-admin", "/phpmyadmin",
  "/api/keys", "/config", "/backup", "/uploads", "/static/main.js", "/health", "/metrics", "/page34", "/page12",
];

export const IP_POOLS = {
  block:  ["185.220.101.45", "45.142.212.100", "198.235.24.55", "91.108.4.100", "193.32.127.11", "194.165.16.99"],
  tarpit: ["192.168.1.55", "103.21.244.0", "185.156.73.11", "10.0.0.55", "172.31.0.44", "10.8.0.12"],
  allow:  ["66.249.64.1", "54.92.1.1", "66.249.64.12", "172.16.0.42", "8.8.8.8", "1.1.1.1", "34.120.54.10"],
};

export function generateEntry(): Omit<LogEntry, "id" | "time" | "ts"> {
  const r = Math.random();
  let action: Action;
  if (r < 0.25) action = "block";
  else if (r < 0.50) action = "tarpit";
  else action = "allow";

  const pool = IP_POOLS[action];
  const ip = pool[Math.floor(Math.random() * pool.length)];
  const path = PATHS[Math.floor(Math.random() * PATHS.length)];
  const score =
    action === "block"  ? 75 + Math.floor(Math.random() * 25) :
    action === "tarpit" ? 40 + Math.floor(Math.random() * 35) :
                           0  + Math.floor(Math.random() * 40);
  return { ip, path, score, action, timestamp: Date.now() };
}