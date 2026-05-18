import Navbar from "./components/layout/Navbar";
import Footer from "./components/layout/Footer";
import Hero from "./components/sections/Hero";
import Methodology from "./components/sections/Methodology";
import Features from "./components/sections/Features";
import Quickstart from "./components/sections/Quickstart";

export default function Home() {
  return (
    <main className="min-h-screen">
      <Navbar />
      <Hero />
      <Methodology />
      <Features />
      <Footer />
    </main>
  );
}