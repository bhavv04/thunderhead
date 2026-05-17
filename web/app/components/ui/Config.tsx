const configJson = `{
  "listen_addr": ":8080",
  "upstream_url": "http://localhost:3000",
  "thresholds": {
    "tarpit": 40,
    "block": 75
  },
  "allowlist": {
    "ips": [],
    "user_agents": ["Googlebot", "Bingbot"]
  },
  "blocklist": {
    "cidrs": [],
    "ips": []
  }
}`;

export default function ConfigBlock() {
  return (
    <div className="border-2 border-ink rounded-xl overflow-hidden">
      <div className="bg-ink px-6 py-3 flex items-center gap-2 border-b-2 border-ink">
        <span className="w-3 h-3 rounded-full bg-danger border border-ink"></span>
        <span className="w-3 h-3 rounded-full bg-warn border border-ink"></span>
        <span className="w-3 h-3 rounded-full bg-signal border border-ink"></span>
        <span className="ml-2 text-cream/40 text-xs">config.json</span>
      </div>
      <div className="bg-ink/95 text-zinc-300 text-sm px-6 py-5 overflow-x-auto">
        <pre>{configJson}</pre>
      </div>
    </div>
  );
}