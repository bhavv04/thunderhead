const steps = [
  {
    step: "01",
    title: "Install",
    code: "go install github.com/bhavdeeparora/thunderhead/cmd/thunderhead@latest",
  },
  {
    step: "02",
    title: "Run with defaults",
    code: "thunderhead",
  },
  {
    step: "03",
    title: "Or point it at your upstream",
    code: "thunderhead -config config.json",
  },
];

const config = `{
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

export default function Quickstart() {
  return (
    <section id="quickstart" className="px-8 py-24 border-b border-black">
      <div className="max-w-4xl mx-auto">
        <div className="inline-block bg-black text-white text-xs font-bold px-3 py-1 rounded-full mb-6 uppercase tracking-widest">
          Quickstart
        </div>
        <h2 className="text-4xl font-black tracking-tighter mb-4">
          Up and running in 60 seconds.
        </h2>
        <p className="text-zinc-600 mb-16 max-w-xl">
          Thunderhead sits in front of any HTTP upstream. No code changes to your app required.
        </p>

        {/* Steps */}
        <div className="flex flex-col gap-4 mb-16">
          {steps.map((s, i) => (
            <div key={i} className="flex items-start gap-6 border border-black rounded-xl p-6">
              <div className="text-4xl font-black text-zinc-200 leading-none">{s.step}</div>
              <div className="flex-1">
                <div className="font-bold text-sm mb-2">{s.title}</div>
                <div className="bg-zinc-950 text-green-400 font-mono text-sm px-4 py-3 rounded-lg">
                  $ {s.code}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Config example */}
        <h3 className="text-sm font-bold uppercase tracking-widest mb-4 text-zinc-500">
          Example config.json
        </h3>
        <div className="bg-zinc-950 text-zinc-300 font-mono text-sm px-6 py-5 rounded-xl border border-black overflow-x-auto">
          <pre>{config}</pre>
        </div>
      </div>
    </section>
  );
}