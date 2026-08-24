"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { Page, Action, LogEntry, Counts } from "./types";
import { generateEntry } from "./data";
import { getTime, downloadCSV } from "./utils";
import { Btn } from "./components/ui";
import { Sidebar } from "./components/Sidebar";
import { OverviewPage } from "./pages/OverviewPage";
import { LiveFeedPage } from "./pages/LiveFeedPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";
import { ThresholdsPage } from "./pages/ThresholdsPage";
import { AllowlistPage } from "./pages/AllowlistPage";
import { SignalsPage } from "./pages/SignalsPage";
import { LogsPage } from "./pages/LogsPage";
import { SettingsPage } from "./pages/SettingsPage";
import type { TrafficBucket } from "./components/charts";
import { SEED_LOGS, SEED_COUNTS, SEED_TRAFFIC } from "./seed";
import {
  LayoutDashboard, Rss, BarChart3, SlidersHorizontal,
  ShieldCheck, Radio, ScrollText, Settings,
} from "lucide-react";

// ─── Helpers ─────────────────────────────────────────────────────────────

/** One bucket of simulated traffic. `spikeChance` controls how often a burst happens. */
function randomBucket(i: number, spikeChance: number): TrafficBucket {
  const base = 4 + Math.sin(i * 0.3) * 2 + Math.random() * 3;
  const spike = Math.random() < spikeChance ? 5 + Math.random() * 4 : 0;
  return {
    allow: Math.round(Math.max(base + spike, 1)),
    tarpit: Math.round(Math.random() < 0.35 ? 1 + Math.random() * 2 : 0),
    block: Math.round(Math.random() < 0.12 ? 1 : 0),
  };
}

function seedTraffic(size = 60): TrafficBucket[] {
  return Array.from({ length: size }, (_, i) => randomBucket(i, i % 13 === 0 ? 1 : 0));
}

function classify(score: number, thresholds: { tarpit: number; block: number }): Action {
  if (score >= thresholds.block) return "block";
  if (score >= thresholds.tarpit) return "tarpit";
  return "allow";
}

const PAGE_TITLE: Record<Page, string> = {
  Overview: "Overview", "Live feed": "Live feed", Analytics: "Analytics",
  Thresholds: "Thresholds", Allowlist: "Allowlist", Signals: "Signals",
  Logs: "Logs", Settings: "Settings",
};

const PAGE_ICON: Record<Page, React.ComponentType<{ className?: string }>> = {
  "Overview": LayoutDashboard,
  "Live feed": Rss,
  "Analytics": BarChart3,
  "Thresholds": SlidersHorizontal,
  "Allowlist": ShieldCheck,
  "Signals": Radio,
  "Logs": ScrollText,
  "Settings": Settings,
};

// ─── Main ────────────────────────────────────────────────────────────────

export default function Demo() {
  const [logs, setLogs] = useState<LogEntry[]>(SEED_LOGS);
  const [counts, setCounts] = useState<Counts>(SEED_COUNTS);
  const [clock, setClock] = useState<string | null>(null);
  const [sparkData, setSparkData] = useState<number[]>(new Array(20).fill(0));
  const [rpsDisplay, setRpsDisplay] = useState(0);
  const [page, setPage] = useState<Page>("Overview");
  const [proxyUp, setProxyUp] = useState(true);
  const [latency, setLatency] = useState(12);
  const [thresholds, setThresholds] = useState({ tarpit: 40, block: 75 });
  const [trafficBuckets, setTrafficBuckets] = useState<TrafficBucket[]>(SEED_TRAFFIC);

  const requestsThisSecond = useRef(0);
  const nextId = useRef(SEED_LOGS.length);

  const addEntry = useCallback(() => {
    if (!proxyUp) return;
    const base = generateEntry();
    const action = classify(base.score, thresholds);
    const entry: LogEntry = { ...base, action, id: ++nextId.current, time: getTime(), ts: Date.now() };

    setLogs(prev => [...prev.slice(-499), entry]);
    setCounts(prev => ({ ...prev, total: prev.total + 1, [action]: prev[action] + 1 }));
    requestsThisSecond.current += 1;
  }, [proxyUp, thresholds]);

  useEffect(() => {
    let cancelled = false;
    let timeout: ReturnType<typeof setTimeout>;
    const schedule = () => {
      const delay = 12_000 + Math.random() * 4_000;
      timeout = setTimeout(() => {
        if (cancelled) return;
        addEntry();
        schedule();
      }, delay);
    };
    schedule();
    return () => { cancelled = true; clearTimeout(timeout); };
  }, [addEntry]);

  useEffect(() => {
    setClock(getTime());
    const interval = setInterval(() => {
      setClock(getTime());

      const rps = requestsThisSecond.current;
      requestsThisSecond.current = 0;
      setRpsDisplay(rps);
      setSparkData(prev => [...prev.slice(1), rps]);
      setTrafficBuckets(prev => [...prev.slice(1), randomBucket(prev.length, 0.08)]);
      setLatency(5 + Math.floor(Math.random() * 30));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const onExport = () => downloadCSV(logs);
  const onRefresh = () => {
    setLogs(SEED_LOGS);
    setCounts(SEED_COUNTS);
  };

  const renderPage = () => {
    switch (page) {
      case "Overview": return <OverviewPage logs={logs} counts={counts} sparkData={sparkData} trafficBuckets={trafficBuckets} rpsDisplay={rpsDisplay} latency={latency} proxyUp={proxyUp} onExport={onExport} onRefresh={onRefresh} />;
      case "Live feed": return <LiveFeedPage logs={logs} onExport={onExport} />;
      case "Analytics": return <AnalyticsPage logs={logs} counts={counts} sparkData={sparkData} trafficBuckets={trafficBuckets} />;
      case "Thresholds": return <ThresholdsPage thresholds={thresholds} onChange={setThresholds} />;
      case "Allowlist": return <AllowlistPage />;
      case "Signals": return <SignalsPage />;
      case "Logs": return <LogsPage logs={logs} onExport={onExport} />;
      case "Settings": return <SettingsPage proxyUp={proxyUp} onToggleProxy={() => setProxyUp(p => !p)} />;
    }
  };

  return (
    <div className="flex h-180 rounded-xl overflow-hidden text-fg bg-zinc-900">
      <Sidebar page={page} setPage={setPage} blockCount={counts.block} proxyUp={proxyUp} latency={latency} />

      <div className="flex-1 flex flex-col overflow-hidden p-2 min-w-0">
        <div className="flex-1 flex flex-col overflow-hidden rounded-lg">
          <div className="h-12 flex items-center justify-between px-5 shrink-0 text-white">
            <div className="flex items-center gap-2">
              {(() => {
                const Icon = PAGE_ICON[page];
                return <Icon className="size-4 text-fg-muted" />;
              })()}
              <span className="text-sm font-medium text-fg">{PAGE_TITLE[page]}</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-fg-subtle tabular-nums">{clock ?? "--:--:--"} UTC</span>
              <div className="flex items-center gap-2">
                <Btn variant="ghost" size="sm" onClick={onRefresh}>Clear</Btn>
                <Btn size="sm" onClick={onExport}>Export</Btn>
              </div>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden">
            {renderPage()}
          </div>
        </div>
      </div>
    </div>
  );
}