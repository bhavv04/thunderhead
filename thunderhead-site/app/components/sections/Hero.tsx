export default function Hero() {
  return (
    <section className="flex flex-col items-center justify-center text-center px-8 py-32 border-b border-black">
      <div className="inline-block bg-yellow-300 text-black text-xs font-bold px-3 py-1 rounded-full mb-6 uppercase tracking-widest">
        Open Source · MIT License
      </div>
      <h1 className="text-6xl font-black tracking-tighter max-w-3xl leading-none mb-6">
        Stop bots before they cost you.
      </h1>
      <p className="text-lg text-zinc-600 max-w-xl mb-10">
        Thunderhead is a lightweight reverse proxy that scores the intent of every
        incoming request — no CAPTCHAs, no Cloudflare, no JS challenges. Just behavior.
      </p>
      <div className="bg-zinc-100 border border-zinc-300 rounded-lg px-5 py-3 text-sm font-mono">
        go install github.com/bhavdeeparora/thunderhead/cmd/thunderhead@latest
      </div>
      <div className="flex items-center gap-6 mt-8 text-sm text-zinc-500">
        <span>✓ Single binary</span>
        <span>✓ Zero dependencies</span>
        <span>✓ Drop-in reverse proxy</span>
      </div>
    </section>
  );
}