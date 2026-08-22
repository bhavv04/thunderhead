"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { Page } from "./types";
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
import type { Action, LogEntry, Counts } from "./types";
import type { TrafficBucket } from "./components/charts";
import { SEED_LOGS, SEED_COUNTS, SEED_TRAFFIC } from "./seed";

// ─── Main ──────────────────────────────────────────────────────────────────────

function generateTrafficSeed(): TrafficBucket[] {
  return Array.from({ length: 60 }, (_, i) => {
    const base = 4 + Math.sin(i * 0.3) * 2 + Math.random() * 3;
    const spike = i % 13 === 0 ? 6 : 0;
    return {
      allow:  Math.round(Math.max(base + spike, 1)),
      tarpit: Math.round(Math.random() < 0.4 ? 1 + Math.random() * 2 : 0),
      block:  Math.round(Math.random() < 0.15 ? 1 : 0),
    };
  });
}

export default function Demo() {
  const BASE = 47_832;
  const [logs, setLogs]     = useState<LogEntry[]>(SEED_LOGS);
  const [counts, setCounts] = useState<Counts>(SEED_COUNTS);
  const [clock, setClock]           = useState<string | null>(null);
  const [sparkData, setSparkData]   = useState<number[]>(new Array(20).fill(0));
  const [rpsDisplay, setRpsDisplay] = useState(0);
  const [page, setPage]             = useState<Page>("Overview");
  const [proxyUp, setProxyUp]       = useState(true);
  const [latency, setLatency]       = useState(12);
  const [thresholds, setThresholds] = useState({ tarpit: 40, block: 75 });
  const [trafficBuckets, setTrafficBuckets] = useState<TrafficBucket[]>(SEED_TRAFFIC);

  const accumRef = useRef(0);
  const idRef = useRef(SEED_LOGS.length);

  const addEntry = useCallback(() => {
    if (!proxyUp) return;
    const base = generateEntry();
    const action: Action =
      base.score >= thresholds.block  ? "block"  :
      base.score >= thresholds.tarpit ? "tarpit" : "allow";
    const entry: LogEntry = { ...base, action, id: ++idRef.current, time: getTime(), ts: Date.now() };
    setLogs(prev => [...prev.slice(-499), entry]);
    setCounts(prev => ({
      total:  prev.total  + 1,
      allow:  prev.allow  + (action === "allow"  ? 1 : 0),
      tarpit: prev.tarpit + (action === "tarpit" ? 1 : 0),
      block:  prev.block  + (action === "block"  ? 1 : 0),
    }));
    accumRef.current += 1;
  }, [proxyUp, thresholds]);

  useEffect(() => {
    let timeout: ReturnType<typeof setTimeout>;
    let mounted = true;
    const schedule = () => {
      const delay = Math.floor(Math.random() * 4000) + 12000;
      timeout = setTimeout(() => { if (!mounted) return; addEntry(); schedule(); }, delay);
    };
    schedule();
    return () => { mounted = false; clearTimeout(timeout); };
  }, [addEntry]);

  useEffect(() => {
    setClock(getTime());
    const interval = setInterval(() => {
      setClock(getTime());
      const rps = accumRef.current;
      accumRef.current = 0;
      setRpsDisplay(rps);
      setSparkData(prev => [...prev.slice(1), rps]);
      setTrafficBuckets(prev => {
        const base = 4 + Math.sin(prev.length * 0.3) * 2 + Math.random() * 3;
        const spike = Math.random() < 0.08 ? 5 + Math.random() * 4 : 0;
        return [
          ...prev.slice(1),
          {
            allow:  Math.round(Math.max(base + spike, 1)),
            tarpit: Math.round(Math.random() < 0.35 ? 1 + Math.random() * 2 : 0),
            block:  Math.round(Math.random() < 0.12 ? 1 : 0),
          },
        ];
      });
      setLatency(Math.floor(Math.random() * 30) + 5);
    }, 1000);
    return () => clearInterval(interval);
  }, [proxyUp]);

  const onExport  = () => downloadCSV(logs);
  const onRefresh = () => {
    setLogs(SEED_LOGS);
    setCounts(SEED_COUNTS);
  };

  const pageTitle: Record<Page, string> = {
    "Overview": "Overview", "Live feed": "Live feed", "Analytics": "Analytics",
    "Thresholds": "Thresholds", "Allowlist": "Allowlist", "Signals": "Signals",
    "Logs": "Logs", "Settings": "Settings",
  };

  const renderPage = () => {
    switch (page) {
      case "Overview": return <OverviewPage logs={logs} counts={counts} sparkData={sparkData} trafficBuckets={trafficBuckets} rpsDisplay={rpsDisplay} latency={latency} proxyUp={proxyUp} onExport={onExport} onRefresh={onRefresh} />;
      case "Live feed":  return <LiveFeedPage logs={logs} onExport={onExport} />;
      case "Analytics":  return <AnalyticsPage logs={logs} counts={counts} sparkData={sparkData} trafficBuckets={trafficBuckets} />;
      case "Thresholds": return <ThresholdsPage thresholds={thresholds} onChange={setThresholds} />;
      case "Allowlist":  return <AllowlistPage />;
      case "Signals":    return <SignalsPage />;
      case "Logs":       return <LogsPage logs={logs} onExport={onExport} />;
      case "Settings":   return <SettingsPage proxyUp={proxyUp} onToggleProxy={() => setProxyUp(p => !p)} />;
    }
  };

  return (
    <div className="flex h-[640px] rounded-xl overflow-hidden text-zinc-100 font-sans border border-white/5">
      <Sidebar page={page} setPage={setPage} blockCount={counts.block} proxyUp={proxyUp} latency={latency} />

      <div className="flex-1 flex flex-col overflow-hidden bg-bg-canvas min-w-0">
        {/* Topbar */}
        <div className="bg-zinc-900 border-b border-zinc-800 h-12 flex items-center justify-between px-5 shrink-0">
          <span className="text-sm font-medium text-zinc-100">{pageTitle[page]}</span>
          <div className="flex items-center gap-3">
            <span className="text-xs text-zinc-500 tabular-nums">{clock ?? "--:--:--"} UTC</span>
            <div className="flex items-center gap-2">
              <Btn variant="ghost" size="sm" onClick={onRefresh}>Clear</Btn>
              <Btn size="sm" onClick={onExport}>Export</Btn>
            </div>
          </div>
        </div>

        {renderPage()}
      </div>
    </div>
  );
}