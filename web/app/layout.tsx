import type { Metadata } from "next";
import { Geist_Mono, Inter } from "next/font/google";
import "./globals.css";
import { cn } from "@/lib/utils";

const inter = Inter({subsets:['latin'],variable:'--font-sans'});

const mono = Geist_Mono({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Thunderhead",
  description: "Passive intent-scoring reverse proxy. No CAPTCHAs, no Cloudflare — just behavior.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={cn("font-sans", inter.variable)}>
      <body className={mono.className}>{children}</body>
    </html>
  );
}