"use client";

import { useState } from "react";

const links = [
	{ label: "Methodology", href: "#methodology" },
	{ label: "Features", href: "#features" },
	{ label: "GitHub", href: "https://github.com/bhavv04/thunderhead" },
];

export default function Navbar() {
	const [open, setOpen] = useState(false);

	return (
		<header className="sticky top-0 z-50 border-b border-white/10 bg-zinc-950/95 backdrop-blur-xl">
			<div className="mx-auto flex w-full max-w-7xl items-center justify-between px-4 py-3 sm:px-6 lg:px-8">
				<a href="#top" className="flex items-center gap-3" onClick={() => setOpen(false)}>
					<div>
						<div className="text-lg text-white/90">
							thunderhead
						</div>
						<div className="text-xs text-white/45">
							Passive intent scoring
						</div>
					</div>
				</a>

				<nav className="hidden items-center gap-8 md:flex" aria-label="Primary navigation">
					{links.map((link) => (
						<a
							key={link.label}
							href={link.href}
							className="text-sm text-white/65 transition-colors hover:text-white"
						>
							{link.label}
						</a>
					))}
				</nav>

				<div className="hidden items-center gap-3 md:flex">
					<a
						href="#methodology"
						className="rounded-full border border-white/10 px-4 py-2 text-sm text-white/75 transition-colors hover:border-white/20 hover:text-white"
					>
						Learn more
					</a>
					<a
						href="https://github.com/bhavv04/thunderhead"
						target="_blank"
						rel="noreferrer"
						className="rounded-full bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black transition-opacity hover:opacity-90"
					>
						View on GitHub
					</a>
				</div>

				<button
					type="button"
					className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-white/80 transition-colors hover:border-white/20 hover:bg-white/10 md:hidden"
					aria-label={open ? "Close menu" : "Open menu"}
					aria-expanded={open}
					onClick={() => setOpen((value) => !value)}
				>
					<span className="flex flex-col gap-1.5">
						<span className={`h-0.5 w-5 rounded-full bg-current transition-transform ${open ? "translate-y-2 rotate-45" : ""}`} />
						<span className={`h-0.5 w-5 rounded-full bg-current transition-opacity ${open ? "opacity-0" : ""}`} />
						<span className={`h-0.5 w-5 rounded-full bg-current transition-transform ${open ? "-translate-y-2 -rotate-45" : ""}`} />
					</span>
				</button>
			</div>

			<div className={`border-t border-white/10 bg-zinc-950/95 px-4 pb-4 pt-2 backdrop-blur-xl md:hidden ${open ? "block" : "hidden"}`}>
				<nav className="mx-auto flex w-full max-w-7xl flex-col gap-2" aria-label="Mobile navigation">
					{links.map((link) => (
						<a
							key={link.label}
							href={link.href}
							onClick={() => setOpen(false)}
							className="rounded-2xl px-4 py-3 text-sm text-white/75 transition-colors hover:bg-white/5 hover:text-white"
						>
							{link.label}
						</a>
					))}

					<div className="mt-2 flex gap-3 px-1">
						<a
							href="#features"
							onClick={() => setOpen(false)}
							className="flex-1 rounded-full border border-white/10 px-4 py-3 text-center text-sm text-white/80 transition-colors hover:border-white/20 hover:text-white"
						>
							Learn more
						</a>
						<a
							href="https://github.com/bhavv04/thunderhead"
							target="_blank"
							rel="noreferrer"
							onClick={() => setOpen(false)}
							className="flex-1 rounded-full bg-[var(--accent)] px-4 py-3 text-center text-sm font-semibold text-black transition-opacity hover:opacity-90"
						>
							View on GitHub
						</a>
					</div>
				</nav>
			</div>
		</header>
	);
}
