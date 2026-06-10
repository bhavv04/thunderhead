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

function getTime() {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

function getBadge(action: string) {
  switch (action) {
    case "block":  return "badge badge-red";
    case "tarpit": return "badge badge-amber";
    default:       return "badge badge-green";
  }
}

function getScoreColor(action: string) {
  switch (action) {
    case "block":  return "var(--red)";
    case "tarpit": return "var(--amber)";
    default:       return "var(--green)";
  }
}

export default function LogFeed() {
  const [logs, setLogs]       = useState<LogEntry[]>([]);
  const [counter, setCounter] = useState(0);
  const viewportRef           = useRef<HTMLDivElement | null>(null);
  const poolIndexRef          = useRef(0);

  useEffect(() => {
    let timeout: ReturnType<typeof setTimeout>;
    let isMounted = true;

    const scheduleNext = () => {
      const delay = Math.floor(Math.random() * 2000) + 1000;
      timeout = setTimeout(() => {
        if (!isMounted) return;
        const entry = LOG_POOL[poolIndexRef.current % LOG_POOL.length];
        poolIndexRef.current += 1;
        const newLog: LogEntry = { ...entry, id: Date.now() + poolIndexRef.current, time: getTime() };
        setLogs((prev) => [...prev, newLog].slice(-60));
        setCounter((c) => c + 1);
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
      className="overflow-hidden rounded-xl border border-white/10 bg-zinc-950"
      style={{
        background: "linear-gradient(180deg, rgba(12,12,13,0.98) 0%, rgba(0,0,0,1) 100%)",
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-green-500/80" />
          </div>
          <span className="text-xs uppercase tracking-wide text-zinc-500">request.log</span>
        </div>
        <span className="text-xs text-zinc-500">
          {counter} requests processed
        </span>
      </div>

      {/* Log body */}
      <div
        ref={viewportRef}
        className="flex h-85 flex-col overflow-y-auto bg-black/20 text-[10px] sm:text-[12px] scrollbar-none" //use px because xs is small enoughh
      >
        {logs.length === 0 && (
          <div className="px-4 py-4 text-sm text-zinc-500 animate-fade-in">
            waiting for requests...
          </div>
        )}

        {logs.map((log) => (
          <div
            key={log.id}
            className="flex items-center gap-3 border-b border-white/5 px-4 py-2 whitespace-nowrap animate-fade-in"
          >
            <span className="w-[19ch] shrink-0 text-zinc-600">
              {log.time}
            </span>

            <span className="text-zinc-500">{log.action}</span>

            <span className="text-zinc-600">score</span>
            <span
              className="w-[2.5rem] text-right"
              style={{ color: getScoreColor(log.action) }}
            >
              {log.score}
            </span>

            <span className="w-[11rem] shrink-0 truncate text-zinc-500">
              {log.ip}
            </span>

            <span className="flex-1 truncate text-zinc-300">
              {log.path}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}