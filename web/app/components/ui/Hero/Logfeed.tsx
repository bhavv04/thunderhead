"use client";

import { useEffect, useRef, useState } from "react";

const LOG_POOL = [
  { ip: "185.220.101.45", method: "GET", path: "/admin",    score: 91, action: "block"  },
  { ip: "66.249.64.1",    method: "GET", path: "/",         score: 0,  action: "allow"  },
  { ip: "192.168.1.55",   method: "GET", path: "/page34",   score: 54, action: "tarpit" },
  { ip: "45.142.212.100", method: "GET", path: "/private",  score: 95, action: "block"  },
  { ip: "Mozilla/5.0",    method: "GET", path: "/about",    score: 8,  action: "allow"  },
  { ip: "103.21.244.0",   method: "GET", path: "/page12",   score: 42, action: "tarpit" },
  { ip: "198.235.24.55",  method: "GET", path: "/internal", score: 88, action: "block"  },
  { ip: "66.249.64.12",   method: "GET", path: "/blog",     score: 2,  action: "allow"  },
  { ip: "185.156.73.11",  method: "GET", path: "/page01",   score: 61, action: "tarpit" },
  { ip: "91.108.4.100",   method: "GET", path: "/secret",   score: 99, action: "block"  },
];

type LogEntry = (typeof LOG_POOL)[0] & { id: number; time: string };

type Stats = { block: number; tarpit: number; allow: number };

function getTime() {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

function getScoreColor(action: string) {
  if (action === "block")  return "#f87171";
  if (action === "tarpit") return "#fbbf24";
  return "#4ade80";
}

function Badge({ action }: { action: string }) {
  const styles: Record<string, React.CSSProperties> = {
    block: {
      background: "rgba(239,68,68,0.12)",
      color: "#f87171",
      border: "0.5px solid rgba(239,68,68,0.2)",
    },
    tarpit: {
      background: "rgba(245,158,11,0.10)",
      color: "#fbbf24",
      border: "0.5px solid rgba(245,158,11,0.2)",
    },
    allow: {
      background: "rgba(34,197,94,0.08)",
      color: "#4ade80",
      border: "0.5px solid rgba(34,197,94,0.15)",
    },
  };

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "2px 7px",
        borderRadius: 4,
        fontSize: 10,
        fontWeight: 500,
        letterSpacing: "0.04em",
        textTransform: "uppercase",
        ...styles[action],
      }}
    >
      {action}
    </span>
  );
}

function ScoreBar({ score, action }: { score: number; action: string }) {
  const color = getScoreColor(action);
  return (
    <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
      <span
        style={{
          width: 28,
          height: 3,
          borderRadius: 2,
          background: "rgba(255,255,255,0.07)",
          overflow: "hidden",
          display: "block",
        }}
      >
        <span
          style={{
            display: "block",
            width: `${score}%`,
            height: "100%",
            borderRadius: 2,
            background: color,
          }}
        />
      </span>
      <span style={{ fontSize: 11, minWidth: 22, textAlign: "right", color }}>
        {score}
      </span>
    </span>
  );
}

export default function LogFeed() {
  const [logs, setLogs]       = useState<LogEntry[]>([]);
  const [counter, setCounter] = useState(0);
  const [stats, setStats]     = useState<Stats>({ block: 0, tarpit: 0, allow: 0 });
  const [lastTime, setLastTime] = useState<string | null>(null);
  const viewportRef           = useRef<HTMLDivElement | null>(null);
  const poolIndexRef          = useRef(0);

  useEffect(() => {
    let timeout: ReturnType<typeof setTimeout>;
    let isMounted = true;

    const scheduleNext = () => {
      const delay = Math.floor(Math.random() * 2000) + 800;
      timeout = setTimeout(() => {
        if (!isMounted) return;
        const entry = LOG_POOL[poolIndexRef.current % LOG_POOL.length];
        poolIndexRef.current += 1;
        const time = getTime();
        const newLog: LogEntry = { ...entry, id: Date.now() + poolIndexRef.current, time };
        setLogs((prev) => [...prev, newLog].slice(-60));
        setCounter((c) => c + 1);
        setStats((s) => ({ ...s, [entry.action]: s[entry.action as keyof Stats] + 1 }));
        setLastTime(time);
        scheduleNext();
      }, delay);
    };

    scheduleNext();
    return () => { isMounted = false; clearTimeout(timeout); };
  }, []);

  useEffect(() => {
    const vp = viewportRef.current;
    if (vp) vp.scrollTop = vp.scrollHeight;
  }, [logs]);

  return (
    <div
      style={{
        background: "#0a0a0b",
        borderRadius: 12,
        border: "0.5px solid rgba(255,255,255,0.08)",
        overflow: "hidden",
        fontFamily: "inherit",
      }}
    >
      {/* ── Header ── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 16px",
          borderBottom: "0.5px solid rgba(255,255,255,0.07)",
          background: "#0f0f10",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ display: "flex", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#ef4444", opacity: 0.75, display: "block" }} />
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#f59e0b", opacity: 0.75, display: "block" }} />
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#22c55e", opacity: 0.75, display: "block" }} />
          </div>
          <span style={{ fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: "#555" }}>
            request.log
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: "50%",
              background: "",
              display: "block",
            }}
          />
          <span style={{ fontSize: 11, color: "#444" }}>
            {counter} request{counter !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      {/* ── Stats bar ── */}
      <div
        style={{
          display: "flex",
          borderBottom: "0.5px solid rgba(255,255,255,0.06)",
          background: "#0d0d0e",
        }}
      >
        {(["block", "tarpit", "allow"] as const).map((type, i) => (
          <div
            key={type}
            style={{
              flex: 1,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 6,
              padding: "7px 0",
              borderRight: i < 2 ? "0.5px solid rgba(255,255,255,0.05)" : undefined,
            }}
          >
            <span
              style={{
                fontSize: 13,
                fontWeight: 500,
                color: type === "block" ? "#f87171" : type === "tarpit" ? "#fbbf24" : "#4ade80",
              }}
            >
              {stats[type]}
            </span>
            <span
              style={{
                fontSize: 10,
                textTransform: "uppercase",
                letterSpacing: "0.07em",
                color: type === "block" ? "#7f3535" : type === "tarpit" ? "#7a5a1a" : "#245e35",
              }}
            >
              {type === "block" ? "blocked" : type === "tarpit" ? "tarpitted" : "allowed"}
            </span>
          </div>
        ))}
      </div>

      {/* ── Log rows ── */}
      <div
        ref={viewportRef}
        style={{
          height: 260,
          overflowY: "auto",
          scrollbarWidth: "none",
          background: "rgba(0,0,0,0.2)",
        }}
      >
        {logs.length === 0 && (
          <div style={{ padding: "24px 16px", fontSize: 12, color: "#333" }}>
            waiting for requests…
          </div>
        )}

        {logs.map((log) => (
          <div
            key={log.id}
            style={{
              display: "grid",
              gridTemplateColumns: "160px 90px 60px 150px 1fr",
              alignItems: "center",
              padding: "5px 16px",
              borderBottom: "0.5px solid rgba(255,255,255,0.04)",
              fontSize: 11.5,
            }}
          >
            <span style={{ color: "#3a3a3d", fontSize: 11, letterSpacing: "0.01em" }}>
              {log.time}
            </span>
            <span>
              <Badge action={log.action} />
            </span>
            <ScoreBar score={log.score} action={log.action} />
            <span style={{ color: "#3f3f42", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {log.ip}
            </span>
            <span style={{ color: "#9ca3af", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {log.path}
            </span>
          </div>
        ))}
      </div>

      {/* ── Footer ── */}
      <div
        style={{
          padding: "6px 16px",
          borderTop: "0.5px solid rgba(255,255,255,0.05)",
          display: "flex",
          justifyContent: "flex-end",
          background: "#0d0d0e",
        }}
      >
        <span style={{ fontSize: 10, color: "#2e2e31", letterSpacing: "0.03em" }}>
          {lastTime ? `last: ${lastTime}` : "stream active"}
        </span>
      </div>

      {/* ── Keyframes ── */}
      <style>{`
        @keyframes lf-pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.3; }
        }
        @keyframes lf-fadeSlide {
          from { opacity: 0; transform: translateY(4px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}