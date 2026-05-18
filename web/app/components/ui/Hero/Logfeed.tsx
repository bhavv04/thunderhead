"use client";

import { useEffect, useRef, useState } from "react";

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
];

type LogEntry = (typeof LOG_POOL)[0] & { id: number; time: string };

function getTime() {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

function getBadge(action: string) {
  switch (action) {
    case "block":
      return "badge-red";
    case "tarpit":
      return "badge-amber";
    default:
      return "badge-green";
  }
}

function getScoreTone(action: string) {
  switch (action) {
    case "block":
      return "var(--red)";
    case "tarpit":
      return "var(--amber)";
    default:
      return "var(--green)";
  }
}

export default function LogFeed() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [counter, setCounter] = useState(0);
  const logViewportRef = useRef<HTMLDivElement | null>(null);
  const poolIndexRef = useRef(0);

  useEffect(() => {
    let timeout: ReturnType<typeof setTimeout>;
    let isMounted = true;

    const scheduleNext = () => {
      const delay = Math.floor(Math.random() * (3000 - 1000 + 1)) + 1000;

      timeout = setTimeout(() => {
        if (!isMounted) {
          return;
        }

        const entry = LOG_POOL[poolIndexRef.current % LOG_POOL.length];
        const entryId = Date.now() + poolIndexRef.current;
        poolIndexRef.current += 1;

        const newLog: LogEntry = {
          ...entry,
          id: entryId,
          time: getTime(),
        };

        setLogs((prev) => [...prev, newLog].slice(-60));
        setCounter((c) => c + 1);

        scheduleNext();
      }, delay);
    };

    scheduleNext();
    return () => {
      isMounted = false;
      clearTimeout(timeout);
    };
  }, []);

  useEffect(() => {
    const viewport = logViewportRef.current;
    if (!viewport) {
      return;
    }

    viewport.scrollTop = viewport.scrollHeight;
  }, [logs]);

  return (
    <div
      className="card card-sm"
      style={{
        marginTop: "var(--space-6)",
        overflow: "hidden",
        background: "linear-gradient(180deg, rgba(12, 12, 13, 0.96) 0%, rgba(0, 0, 0, 1) 100%)",
        borderColor: "rgba(255, 255, 255, 0.14)",
      }}
    >

      {/* Header */}
      <div
        className="flex items-center justify-between"
        style={{
          paddingBottom: "var(--space-3)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div className="flex items-center" style={{ gap: "var(--space-3)" }}>
          <div className="flex" style={{ gap: "var(--space-1)" }}>
            <span
              style={{
                width: "10px",
                height: "10px",
                borderRadius: "var(--radius-full)",
                backgroundColor: "rgba(239, 68, 68, 0.8)",
              }}
            />
            <span
              style={{
                width: "10px",
                height: "10px",
                borderRadius: "var(--radius-full)",
                backgroundColor: "rgba(245, 158, 11, 0.8)",
              }}
            />
            <span
              style={{
                width: "10px",
                height: "10px",
                borderRadius: "var(--radius-full)",
                backgroundColor: "rgba(34, 197, 94, 0.8)",
              }}
            />
          </div>

          <span className="label">request.log</span>
        </div>

        <div className="text-muted mono" style={{ fontSize: "var(--text-xs)", letterSpacing: "0.04em" }}>
          {counter} requests processed
        </div>
      </div>

      {/* Log body */}
      <div
        ref={logViewportRef}
        className="flex flex-col"
        style={{
          marginTop: "var(--space-3)",
          height: "16rem",
          overflowY: "auto",
          paddingRight: "var(--space-1)",
          fontFamily: "var(--font-mono)",
          backgroundColor: "rgba(255, 255, 255, 0.01)",
          border: "1px solid rgba(255, 255, 255, 0.06)",
          borderRadius: "var(--radius-md)",
        }}
      >
        <div
          className="text-muted"
          style={{
            fontSize: "var(--text-xs)",
            padding: "var(--space-2) var(--space-3)",
            borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
            letterSpacing: "0.04em",
            textTransform: "uppercase",
          }}
        >
          live request stream
        </div>

        {logs.length === 0 && (
          <div
            className="text-muted animate-fade-in"
            style={{ fontSize: "var(--text-sm)", padding: "var(--space-3)" }}
          >
            waiting for requests...
          </div>
        )}

        {logs.map((log) => (
          <div
            key={log.id}
            className="flex items-center animate-fade-in"
            style={{
              gap: "var(--space-3)",
              fontSize: "var(--text-sm)",
              padding: "0.4rem var(--space-3)",
              borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
              whiteSpace: "nowrap",
            }}
          >
            {/* Time */}
            <span
              className="text-muted mono"
              style={{ fontSize: "var(--text-xs)", width: "19ch", flexShrink: 0, opacity: 0.85 }}
            >
              {log.time}
            </span>

            {/* Action badge */}
            <span className={`badge ${getBadge(log.action)}`}>
              {log.action}
            </span>

            {/* Score */}
            <span className="text-muted" style={{ fontSize: "var(--text-xs)" }}>score</span>
            <span
              className="mono"
              style={{ width: "2.25rem", textAlign: "right", color: getScoreTone(log.action) }}
            >
              {log.score}
            </span>

            {/* IP */}
            <span
              className="text-muted mono truncate"
              style={{ width: "11rem", flexShrink: 0 }}
            >
              {log.ip}
            </span>

            {/* Path */}
            <span className="text-subtle truncate" style={{ flex: 1 }}>
              {log.path}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}