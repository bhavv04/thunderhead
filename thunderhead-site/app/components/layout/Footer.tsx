export default function Footer() {
  return (
    <footer className="px-8 py-12 border-t border-black">
      <div className="max-w-4xl mx-auto flex items-center justify-between">
        <div>
          <div className="font-bold text-lg tracking-tight mb-1">⚡ thunderhead</div>
          <div className="text-sm text-zinc-500">
            Passive intent-scoring reverse proxy. Built in Go.
          </div>
        </div>
        <div className="flex items-center gap-6 text-sm">
            <a
                href="https://github.com/bhavdeeparora/thunderhead"
                target="_blank"
                className="hover:underline"
            >
                GitHub
            </a>
            <a
                href="https://github.com/bhavdeeparora/thunderhead/blob/main/LICENSE"
                target="_blank"
                className="hover:underline"
            >
                License
            </a>
            <a
                href="https://github.com/bhavdeeparora/thunderhead/issues"
                target="_blank"
                className="hover:underline"
            >
            Issues
          </a>
        </div>
      </div>
      <div className="max-w-4xl mx-auto mt-8 pt-6 border-t border-zinc-200 text-xs text-zinc-400 flex justify-between">
        <span>© 2026 Bhav. MIT License.</span>
        <span>Inspired by <a href="https://github.com/TecharoHQ/anubis" className="underline">Anubis</a></span>
      </div>
    </footer>
  );
}