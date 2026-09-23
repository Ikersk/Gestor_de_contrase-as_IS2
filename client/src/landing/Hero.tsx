import { CiphertextVault } from "./CiphertextVault";
import { GlowCta } from "./GlowCta";

type HeroProps = {
  onAccess: () => void;
  reveal: (id: string) => string;
};

export function Hero({ onAccess, reveal }: HeroProps) {
  return (
    <section
      id="hero"
      data-reveal="hero"
      aria-labelledby="hero-title"
      className={`relative z-10 mx-auto grid min-h-[88vh] w-full max-w-6xl items-center gap-14 px-6 pb-24 pt-16 lg:grid-cols-[1.05fr_0.95fr] lg:gap-10 lg:pt-24 ${reveal("hero")}`}
    >
      {/* Copy */}
      <div className="lp-reveal">
        <div className="mb-7 flex flex-wrap items-center gap-3">
          <span className="inline-flex items-center gap-2 rounded-full border border-cyan-electric/40 bg-cyan-electric/8 px-3.5 py-1.5 font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-cyan-electric shadow-[0_0_16px_rgba(6,182,212,0.15)]">
            <span className="h-1.5 w-1.5 animate-pulse-glow rounded-full bg-cyan-electric" />
            Zero-Knowledge
          </span>
          <span className="inline-flex items-center rounded-full border border-line px-3.5 py-1.5 font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-acid">
            AES-256-GCM
          </span>
          <span className="hidden inline-flex items-center rounded-full border border-line px-3.5 py-1.5 font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-ink-dim sm:inline-flex">
            PBKDF2 · 600K
          </span>
        </div>

        <p className="mb-4 font-mono text-[11px] font-bold uppercase tracking-[0.28em] text-cyan-electric">
          Criptografía de grado militar
        </p>

        <h1
          id="hero-title"
          className="font-display text-[clamp(48px,8.5vw,104px)] font-semibold leading-[0.95] tracking-[-0.045em] text-ink"
        >
          Privacidad
          <br />
          <span className="text-cyan-electric text-glow-cyan">absoluta.</span>
          <br />
          <span className="text-ink-dim">Cero testigos.</span>
        </h1>

        <p className="mt-7 max-w-lg text-[16px] leading-relaxed text-ink-dim">
          Arca deriva tus claves en tu navegador y cifra cada credencial antes de
          tocar la red. El servidor solo ve{" "}
          <span className="font-mono text-[13px] text-acid">blobs indescifrables</span>{" "}
          — jamás tus secretos.
        </p>

        <div className="mt-10 flex flex-wrap items-center gap-5">
          <GlowCta onClick={onAccess}>Abrir mi bóveda</GlowCta>
          <a
            href="#arquitectura"
            className="group inline-flex items-center gap-2 font-mono text-[12px] uppercase tracking-[0.16em] text-ink-dim transition hover:text-cyan-electric"
          >
            <span className="border-b border-transparent transition group-hover:border-cyan-electric/60">
              Ver arquitectura
            </span>
            <span aria-hidden="true">↓</span>
          </a>
        </div>

        <dl className="mt-12 grid max-w-md grid-cols-3 gap-4 border-t border-line pt-6">
          {[
            ["0", "secretos en claro"],
            ["100%", "cifrado local"],
            ["5ch", "salen a la red"],
          ].map(([value, label]) => (
            <div key={label}>
              <dt className="sr-only">{label}</dt>
              <dd className="font-mono text-xl font-bold text-ink text-glow-acid">{value}</dd>
              <dd className="mt-1 font-mono text-[9px] uppercase tracking-[0.14em] text-ink-faint">
                {label}
              </dd>
            </div>
          ))}
        </dl>
      </div>

      {/* Caja fuerte digital */}
      <div
        className={`lp-reveal flex justify-center lg:justify-end ${reveal("hero")}`}
        style={{ transitionDelay: "160ms" }}
      >
        <CiphertextVault />
      </div>
    </section>
  );
}
