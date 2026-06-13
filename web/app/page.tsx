import Navbar from "./components/layout/Navbar";
import Footer from "./components/layout/Footer";
import Hero from "./components/sections/Hero";
import Methodology from "./components/sections/Methodology";
import Features from "./components/sections/Features";
import Quickstart from "./components/sections/Quickstart";
import { BackgroundBeams } from "@/components/ui/beams"
import Ferrofluid from '@/components/ui/Ferrofluid'; 

export default function Home() {
  return (
    <main id="top" className="min-h-screen font-sans mesh-bg">
      <Navbar />
      <div className="relative">
        <div className="absolute inset-0 z-0 pointer-events-none">
            <Ferrofluid
                colors={["#10B981","#22d786","#0b4b34"]}
                speed={0.3}
                scale={1.6}
                turbulence={1}
                fluidity={0.1}
                rimWidth={0.2}
                sharpness={2.5}
                shimmer={1.5}
                glow={2}
                flowDirection="up"
                opacity={1}
                mouseInteraction
                mouseStrength={1}
                mouseRadius={0.35}
            />
        </div>
        <div className="relative z-10">
          <Hero />
        </div>
      </div>
      <Methodology />
      <Features />
      <Quickstart />
      <Footer />
    </main>
  );
}