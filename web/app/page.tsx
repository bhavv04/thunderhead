import Navbar from "./components/layout/Navbar";
import Footer from "./components/layout/Footer";
import Hero from "./components/sections/Hero";
import Methodology from "./components/sections/Methodology";
import Features from "./components/sections/Features";

export default function Home() {
  return (
    <main id="top" className="min-h-screen font-sans">
      <Navbar />
      <Hero />
      <Methodology />
      <Features />
      <Footer />
    </main>
  );
}