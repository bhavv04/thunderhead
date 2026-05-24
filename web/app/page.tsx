import Navbar from "./components/layout/Navbar";
import Footer from "./components/layout/Footer";
import Hero from "./components/sections/Hero";
import Methodology from "./components/sections/Methodology";
import Features from "./components/sections/Features";
import Quickstart from "./components/sections/Quickstart";

export default function Home() {
  return (
    <main id="top" className="min-h-screen font-sans mesh-bg">
      <Navbar />
      <Hero />
      <Methodology />
      <Features />
      <Quickstart />
      <Footer />
    </main>
  );
}