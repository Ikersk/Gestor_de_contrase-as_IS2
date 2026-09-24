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
      className={`relative z-10 mx-auto grid min-h-[88vh] w-full max-w-6xl items-center gap-14 px-6 pb-20 pt-16 lg:grid-cols-[1.05fr_0.95fr] lg:gap-5 lg:pt-24 ${reveal("hero")}`}
    >
      {/* Copy */}
      <div className="lp-reveal">
        <h1
          id="hero-title"
          className="font-display text-[clamp(48px,8.5vw,104px)] font-semibold leading-[0.95] tracking-[-0.045em] text-ink"
        >
          Privacidad
          <br />
          <span className="font-display text-[clamp(48px,8.5vw,104px)] font-semibold leading-[0.95] tracking-[-0.045em] text-ink">absoluta.</span>
          <br />
          <span className="font-display text-[clamp(48px,8.5vw,104px)] font-semibold leading-[0.95] tracking-[-0.045em] text-ink">Cero testigos.</span>
          
        </h1>

        <p className="mt-7 max-w-lg text-[16px] leading-relaxed text-ink-dim">
          //
          Arca deriva tus claves en tu navegador y cifra cada credencial antes de
          tocar la red. El servidor solo ve{" "}
          <span className="font-mono text-[13px] text-blue-soft">texto indescifrable</span>{" "}
        </p>

        <div className="mt-10 flex flex-wrap items-center gap-5">
          <GlowCta onClick={onAccess}>Abrir mi bóveda</GlowCta>
          <a
            href="#arquitectura"
            className="group inline-flex items-center gap-2 font-mono text-[12px] uppercase tracking-[0.16em] text-ink-dim transition hover:text-blue-electric"
          >
            <span className="border-b border-transparent transition group-hover:border-blue-electric/60">
              Ver arquitectura
            </span>
            <span aria-hidden="true">↓</span>
          </a>
        </div>

        <dl className="mt-12 grid max-w-md grid-cols-3 gap-4 border-t border-line pt-6">
          {[
            ["0", "secretos en la base de datos"],
            ["0", "llaves en el servidor"],
            ["100%", "cifrado local"],
          ].map(([value, label]) => (
            <div key={label}>
              <dt className="sr-only">{label}</dt>
              <dd className="font-mono text-xl font-bold text-ink text-glow-blue-soft">{value}</dd>
              <dd className="mt-1 font-mono text-[12px] uppercase tracking-[0.14em] text-ink-faint">
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
