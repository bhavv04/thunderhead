import type { Action } from "./types";

// ─── Design tokens ─────────────────────────────────────────────────────────────

export const COLOR: Record<Action, { text: string; bg: string; border: string }> = {
  allow:  { text: "#4ade80", bg: "transparent", border: "transparent" },
  tarpit: { text: "#fbbf24", bg: "transparent", border: "transparent" },
  block:  { text: "#f87171", bg: "transparent", border: "transparent" },
};