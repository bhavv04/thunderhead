import type { Metadata } from "next";
import { Geist_Mono } from "next/font/google";
import "./globals.css";

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
    <html lang="en">
      <body className={mono.className}>{children}</body>
    </html>
  );
}