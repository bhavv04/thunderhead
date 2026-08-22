"use client";

import { useCallback } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/hooks";

function Row({ label, value }: { label: string; value: string | number | boolean }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-zinc-800 last:border-0">
      <span className="text-[11px] text-zinc-400">{label}</span>
      <span className="font-mono text-[12px] text-zinc-100">{String(value)}</span>
    </div>
  );
}

export default function ConfigPage() {
  const fetchConfig = useCallback(() => api.config(), []);
  const { data, error, loading } = usePoll(fetchConfig, 30000);

  if (loading) return <div className="flex-1 flex items-center justify-center text-zinc-500 text-sm">Loading...</div>;
  if (error)   return <div className="flex-1 flex items-center justify-center text-red-400 text-sm">{error}</div>;

  const c = data!;

  return (
    <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h1 className="text-[13px] font-medium text-zinc-100">Config</h1>
        <span className="text-[10px] text-zinc-500">read-only · refreshes every 30s</span>
      </div>

      <div className="bg-zinc-900 border border-zinc-800 rounded-lg px-4">
        <div className="text-[10px] text-zinc-500 uppercase tracking-widest py-2 border-b border-zinc-800">Network</div>
        <Row label="Listen address" value={c.listen_addr}  />
        <Row label="Upstream URL"   value={c.upstream_url} />
      </div>

      <div className="bg-zinc-900 border border-zinc-800 rounded-lg px-4">
        <div className="text-[10px] text-zinc-500 uppercase tracking-widest py-2 border-b border-zinc-800">Thresholds</div>
        <Row label="Tarpit at" value={c.thresholds.tarpit} />
        <Row label="Block at"  value={c.thresholds.block}  />
      </div>

      <div className="bg-zinc-900 border border-zinc-800 rounded-lg px-4">
        <div className="text-[10px] text-zinc-500 uppercase tracking-widest py-2 border-b border-zinc-800">Behaviour</div>
        <Row label="Tarpit delay" value={c.tarpit_delay} />
        <Row label="Expiry days"  value={c.expiry_days}  />
        <Row label="Dry run"      value={c.dry_run}      />
      </div>
    </div>
  );
}