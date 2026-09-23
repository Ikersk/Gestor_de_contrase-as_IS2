import { useRef } from "react";
import { ThemeSwitcher } from "../ThemeSwitcher";
import { FeaturesBento } from "./FeaturesBento";
import { Hero } from "./Hero";
import { TechTerminal } from "./TechTerminal";
import { TextureLayers } from "./TextureLayers";
import { useReveal } from "./useReveal";
import "./landing.css";

type LandingProps = {
  onAccess: () => void;
};

/** Página pública: hero, bento de pilares y terminal de stack + CTA. */
export function Landing({ onAccess }: LandingProps) {
  const rootRef = useRef<HTMLDivElement>(null);
  const reveal = useReveal(rootRef);

  return (
    <div ref={rootRef} className="landing-page relative min-h-screen bg-abyss font-sans text-ink antialiased">
      <TextureLayers />

      {/* Marca de agua de fondo */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-x-0 bottom-0 z-0 flex justify-center overflow-hidden"
      >
        <span className="translate-y-[28%] select-none font-display text-[42vw] font-bold leading-none tracking-tighter text-ink opacity-[0.025]">
          ARCA
        </span>
      </div>

      <header className="relative z-20 mx-auto flex w-full max-w-6xl items-center justify-between gap-6 px-6 py-6">
        <a
          className="group inline-flex items-center gap-2.5 font-display text-[17px] font-semibold tracking-[0.2em] uppercase text-ink"
          href="/"
          aria-label="Arca, inicio"
        >
          <span className="grid h-8 w-8 place-items-center rounded-md bg-cyan-electric font-mono text-[13px] font-bold tracking-normal text-abyss shadow-[0_0_18px_rgba(6,182,212,0.45)] transition-shadow group-hover:shadow-[0_0_28px_rgba(6,182,212,0.7)]">
            A
          </span>
          arca
        </a>

        <nav className="flex items-center gap-7 font-mono text-[11px] uppercase tracking-[0.16em] text-ink-dim" aria-label="Navegación principal">
          <a className="hidden transition hover:text-cyan-electric sm:inline" href="#arquitectura">
            Arquitectura
          </a>
          <a className="hidden transition hover:text-cyan-electric sm:inline" href="#stack">
            Stack
          </a>
          <button
            className="rounded-full border border-line px-4 py-1.5 text-ink transition hover:border-glow hover:text-cyan-electric"
            type="button"
            onClick={onAccess}
          >
            Entrar
          </button>
          <ThemeSwitcher />
        </nav>
      </header>

      <main>
        <Hero onAccess={onAccess} reveal={reveal} />
        <FeaturesBento reveal={reveal} />
        <TechTerminal onAccess={onAccess} reveal={reveal} />
      </main>

      <footer className="relative z-10 mx-auto flex w-full max-w-6xl flex-col gap-3 border-t border-line px-6 py-8 font-mono text-[10px] uppercase tracking-[0.16em] text-ink-faint sm:flex-row sm:items-center sm:justify-between">
        <span>arca / privacidad primero</span>
        <span className="text-ink-dim">
          construido para guardar lo importante · <span className="text-cyan-electric">zk</span>
        </span>
      </footer>
    </div>
  );
}
