const signals = [
  {
    signal: "robots.txt violation",
    weight: "+30",
    description: "Client accessed a path explicitly disallowed in robots.txt",
  },
  {
    signal: "Sequential crawling",
    weight: "+25",
    description: "Paths requested in alphabetical or numeric order — classic scraper pattern",
  },
  {
    signal: "High request rate",
    weight: "+20",
    description: "More than 30 requests within a 60 second window",
  },
  {
    signal: "Suspicious headers",
    weight: "+15",
    description: "Missing or bot-like User-Agent, missing Accept or Accept-Language headers",
  },
  {
    signal: "Text-heavy pattern",
    weight: "+10",
    description: "80%+ of requests hitting only HTML pages — ignoring assets entirely",
  },
];

const actions = [
  {
    range: "0 – 39",
    action: "Allow",
    description: "Pass through to upstream",
    color: "bg-green-400",
  },
  {
    range: "40 – 74",
    action: "Tarpit",
    description: "Delay response by 5 seconds",
    color: "bg-yellow-300",
  },
  {
    range: "75 – 100",
    action: "Block",
    description: "Return 403 Forbidden immediately",
    color: "bg-red-400",
  },
];

export default function Methodology() {
  return (
    <section id="how-it-works" className="px-8 py-24 border-b border-black">
      <div className="max-w-4xl mx-auto">
        <div className="inline-block bg-black text-white text-xs font-bold px-3 py-1 rounded-full mb-6 uppercase tracking-widest">
          How it works
        </div>
        <h2 className="text-4xl font-black tracking-tighter mb-4">
          Every request gets a score.
        </h2>
        <p className="text-zinc-600 mb-16 max-w-xl">
          Thunderhead watches how clients move through your site and builds an intent
          score from 0–100. Legitimate users score low. Bots score high.
        </p>

        {/* Signals table */}
        <h3 className="text-sm font-bold uppercase tracking-widest mb-4 text-zinc-500">
          Scoring signals
        </h3>
        <div className="border border-black rounded-xl overflow-hidden mb-16">
          <table className="w-full text-sm">
            <thead className="bg-zinc-100 border-b border-black">
              <tr>
                <th className="text-left px-5 py-3 font-bold">Signal</th>
                <th className="text-left px-5 py-3 font-bold">Weight</th>
                <th className="text-left px-5 py-3 font-bold">Description</th>
              </tr>
            </thead>
            <tbody>
              {signals.map((s, i) => (
                <tr key={i} className="border-t border-zinc-200">
                  <td className="px-5 py-3 font-mono text-xs">{s.signal}</td>
                  <td className="px-5 py-3">
                    <span className="bg-yellow-300 text-black font-bold text-xs px-2 py-0.5 rounded-full">
                      {s.weight}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-zinc-600">{s.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Actions */}
        <h3 className="text-sm font-bold uppercase tracking-widest mb-4 text-zinc-500">
          Actions
        </h3>
        <div className="grid grid-cols-3 gap-4">
          {actions.map((a, i) => (
            <div key={i} className="border border-black rounded-xl p-5">
              <div className={`inline-block ${a.color} text-black text-xs font-bold px-3 py-1 rounded-full mb-3`}>
                {a.action}
              </div>
              <div className="font-mono text-sm font-bold mb-1">Score {a.range}</div>
              <div className="text-zinc-600 text-sm">{a.description}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}