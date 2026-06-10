import Navbar from "./components/layout/Navbar";
import Footer from "./components/layout/Footer";
import Hero from "./components/sections/Hero";
import Methodology from "./components/sections/Methodology";
import Features from "./components/sections/Features";
import Quickstart from "./components/sections/Quickstart";
import { AuroraBackground } from "@/components/ui/aurora-background";

export default function Home() {
  return (
    <AuroraBackground>
      <main id="top" className="min-h-screen font-sans">
        <Navbar />
        <Hero />
        <div className="relative border-t border-white/10">
            {/* fade from transparent to black */}
                <div className="bg-black/30 backdrop-blur-xl">
                <Methodology />
                <Features />
                <Quickstart />
            </div>
        </div>
        <Footer />
      </main>
    </AuroraBackground>
  );
}