"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function ConnectPage() {
  const router = useRouter();
  const [url,     setUrl]     = useState("http://localhost:8080");
  const [key,     setKey]     = useState("");
  const [error,   setError]   = useState("");
  const [loading, setLoading] = useState(false);
  const [checked, setChecked] = useState(false);

  // if already configured, go straight to overview
  useEffect(() => {
    const savedUrl = localStorage.getItem("th_url");
    const savedKey = localStorage.getItem("th_key");
    if (savedUrl && savedKey) {
      router.replace("/overview");
    } else {
      setChecked(true);
    }
  }, [router]);

  async function handleConnect() {
    setLoading(true);
    setError("");
    localStorage.setItem("th_url", url.replace(/\/$/, ""));
    localStorage.setItem("th_key", key);
    try {
      await api.health();
      router.replace("/overview");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Connection failed");
      localStorage.removeItem("th_url");
      localStorage.removeItem("th_key");
      setLoading(false);
    }
  }

  if (!checked) return null;

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2.5 mb-8">
          <div className="w-7 h-7 rounded-md bg-white flex items-center justify-center shrink-0">
            <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="#09090b" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <polyline points="3,9 7,2 11,9" />
              <line x1={4.5} y1={6.5} x2={9.5} y2={6.5} />
              <line x1={7} y1={9} x2={7} y2={12} />
            </svg>
          </div>
          <div>
            <div className="text-[14px] font-medium text-zinc-100">Thunderhead</div>
            <div className="text-[11px] text-zinc-500">Connect to your instance</div>
          </div>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label className="text-[11px] text-zinc-400 font-medium">Instance URL</label>
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="http://localhost:8080"
              className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-[13px] text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-[11px] text-zinc-400 font-medium">API Key</label>
            <input
              type="password"
              value={key}
              onChange={e => setKey(e.target.value)}
              placeholder="th-dev-secret-1234"
              className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-[13px] text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
              onKeyDown={e => e.key === "Enter" && handleConnect()}
            />
          </div>

          {error && (
            <div className="text-[11px] text-red-400 bg-red-950/30 border border-red-900/50 rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          <button
            onClick={handleConnect}
            disabled={loading || !url || !key}
            className="w-full bg-zinc-100 text-zinc-950 rounded-lg py-2 text-[13px] font-medium hover:bg-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {loading ? "Connecting..." : "Connect"}
          </button>
        </div>

        <p className="text-[11px] text-zinc-600 text-center mt-4">
          Credentials are stored in your browser only.
        </p>
      </div>
    </div>
  );
}