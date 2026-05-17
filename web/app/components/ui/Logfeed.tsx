"use client";

import { useEffect, useState } from "react";

const LOG_POOL = [
  { ip: "185.220.101.45", method: "GET", path: "/admin", score: 91, action: "block" },
  { ip: "66.249.64.1", method: "GET", path: "/", score: 0, action: "allow" },
  { ip: "192.168.1.55", method: "GET", path: "/page34", score: 54, action: "tarpit" },
  { ip: "45.142.212.100", method: "GET", path: "/private", score: 95, action: "block" },
  { ip: "Mozilla/5.0", method: "GET", path: "/about", score: 8, action: "allow" },
  { ip: "103.21.244.0", method: "GET", path: "/page12", score: 42, action: "tarpit" },
  { ip: "198.235.24.55", method: "GET", path: "/internal", score: 88, action: "block" },
  { ip: "66.249.64.12", method: "GET", path: "/blog", score: 2, action: "allow" },
  { ip: "185.156.73.11", method: "GET", path: "/page01", score: 61, action: "tarpit" },
  { ip: "91.108.4.100", method: "GET", path: "/secret", score: 99, action: "block" },
  { ip: "172.16.0.5", method: "GET", path: "/projects", score: 11, action: "allow" },
  { ip: "45.95.168.20", method: "GET", path: "/page22", score: 47, action: "tarpit" },
  { ip: "193.32.127.44", method: "GET", path: "/wp-admin", score: 97, action: "block" },
  { ip: "64.233.160.1", method: "GET", path: "/contact", score: 5, action: "allow" },
  { ip: "178.128.44.90", method: "GET", path: "/page08", score: 58, action: "tarpit" },
];

type LogEntry = typeof LOG_POOL[0] & { id: number; time: string };

function getTime() {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

function getColor(action: string) {
  switch (action) {
    case "block": return "text-danger/80";
    case "tarpit": return "text-warn/80";
    default: return "text-text/40";
  }
}

function getActionColor(action: string) {
  switch (action) {
    case "block": return "text-danger";
    case "tarpit": return "text-warn";
    default: return "text-signal";
  }
}

export default function LogFeed() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [counter, setCounter] = useState(0);
  const [poolIndex, setPoolIndex] = useState(0);

useEffect(() => {
  let timeout: ReturnType<typeof setTimeout>;

  const scheduleNext = () => {
    const delay = Math.floor(Math.random() * (3000 - 1000 + 1)) + 1000;
    timeout = setTimeout(() => {
      const entry = LOG_POOL[poolIndex % LOG_POOL.length];
      const newLog: LogEntry = {
        ...entry,
        id: counter,
        time: getTime(),
      };
      setLogs((prev) => [newLog, ...prev].slice(0, 8));
      setCounter((c) => c + 1);
      setPoolIndex((p) => p + 1);
      scheduleNext();
    }, delay);
  };

  scheduleNext();
  return () => clearTimeout(timeout);
}, [poolIndex, counter]);

  return (
    <div className="border border-border rounded-xl overflow-hidden mt-4">

        <div className="bg-ink w-full px-3.5 sm:px-6 py-3 flex items-center justify-between text-cream text-xs">
        <div className="flex items-center gap-2 text-cream/50">
            <span className="w-3 h-3 rounded-full bg-danger"></span>
            <span className="w-3 h-3 rounded-full bg-warn"></span>
            <span className="w-3 h-3 rounded-full bg-signal"></span>
            <span className="ml-2">request.log</span>
        </div>
        <span className="text-xs">{counter} requests processed</span>
        </div>

      {/* Log entries */}
      <div className="bg-ink/95 text-white px-4 py-3 flex flex-col gap-2 min-h-48 text-xs">
        {logs.length === 0 && (
          <div className="text-muted/40 text-md mt-2">waiting for requests...</div>
        )}
        {logs.map((log) => (
        <div
            key={log.id}
            className="flex items-center gap-2 sm:gap-3 animate-fade-in sm:text-md"
        >
            {/* Hide timestamp on mobile, show on sm+ */}
            <span className="text-muted/40 shrink-0 hidden sm:block">{log.time}</span>

            {/* Short time on mobile only */}
            <span className="text-muted/40 shrink-0 sm:hidden">
            {log.time.slice(11, 19)}
            </span>

            <span className={`shrink-0 w-16 text-right ${getActionColor(log.action)}`}>
            {log.action}
            </span>
            <span className="text-muted/60 shrink-0">score</span>
            <span className={`shrink-0 w-6 ${getColor(log.action)}`}>{log.score}</span>

            {/* Hide IP on mobile */}
            <span className="text-muted/40 shrink-0 hidden md:block">{log.ip}</span>

            <span className="text-muted/60 truncate">{log.path}</span>
        </div>
        ))}
      </div>
    </div>
  );
}