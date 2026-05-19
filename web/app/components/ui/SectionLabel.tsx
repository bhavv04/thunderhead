import type { ReactNode } from "react";

export default function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center text-xs font-bold">
      {children}
    </span>
  );
}