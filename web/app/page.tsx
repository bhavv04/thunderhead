import Navbar from "./components/layout/Navbar";
import Footer from "./components/layout/Footer";
import Hero from "./components/sections/Hero";
import Methodology from "./components/sections/Methodology";
import Features from "./components/sections/Features";
import Quickstart from "./components/sections/Quickstart";
import PlasmaWave  from '@/components/ui/plasmawave'; 

export default function Home() {
  return (
    <main id="top" className="min-h-screen font-sans bg-black/95">
      <Navbar />
<div className="relative">
  <div className="absolute inset-0 z-0 pointer-events-none h-full">
    <PlasmaWave />
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