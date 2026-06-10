import Navbar from "./components/layout/Navbar";
import Footer from "./components/layout/Footer";
import Hero from "./components/sections/Hero";
import Methodology from "./components/sections/Methodology";
import Features from "./components/sections/Features";
import Quickstart from "./components/sections/Quickstart";
import { BackgroundBeams } from "@/components/ui/beams" // adjust path

export default function Home() {
  return (
    <main id="top" className="min-h-screen font-sans bg-neutral-950">
      <BackgroundBeams />
      <Navbar />
      <Hero />
      <Methodology />
      <Features />
      <Quickstart />
      <Footer />
    </main>
  );
}