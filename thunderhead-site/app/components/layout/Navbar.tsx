export default function Navbar() {
  return (
    <nav className="flex items-center justify-between px-8 py-5 border-b border-black">
      <span className="font-bold text-lg tracking-tight">⚡ thunderhead</span>
      <div className="flex items-center gap-6 text-sm">
        <a href="#how-it-works" className="hover:underline">How it works</a>
        <a href="#features" className="hover:underline">Features</a>
        <a href="#quickstart" className="hover:underline">Quickstart</a>
        <a
          href="https://github.com/bhavdeeparora/thunderhead"
          target="_blank"
          className="bg-black text-white px-4 py-1.5 rounded-full hover:bg-zinc-800 transition-colors"
        >
          GitHub →
        </a>
      </div>
    </nav>
  );
}