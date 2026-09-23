import { GlowCta } from "./GlowCta";

type TechTerminalProps = {
  onAccess: () => void;
  reveal: (id: string) => string;
};

type TermLine = {
  text: string;
  kind: "cmd" | "ok" | "dim" | "accent" | "prompt";
};

const stackLines: TermLine[] = [
  { text: "$ arca --inspect-stack --verbose", kind: "cmd" },
  { text: "✓ react 19 + typescript     · SPA con Vite", kind: "ok" },
  { text: "✓ vite + plugin SRI         · integridad sha-384", kind: "ok" },
  { text: "✓ express + pg              · API stateless", kind: "ok" },
  { text: "✓ supabase (postgres)       · solo blobs cifrados", kind: "ok" },
  { text: "✓ web crypto api            · PBKDF2 600K · AES-GCM-256", kind: "accent" },
  { text: "✓ hibp k-anonymity          · prefijo SHA-1 de 5 chars", kind: "accent" },
  { text: "→ 0 secretos legibles almacenados en servidor", kind: "dim" },
];

const KIND_CLASS: Record<TermLine["kind"], string> = {
  cmd: "text-ink font-bold",
  ok: "text-ink-dim",
  accent: "text-blue-electric",
  dim: "text-blue-soft",
  prompt: "text-blue-electric",
};

export function TechTerminal({ onAccess, reveal }: TechTerminalProps) {
  return (
    <section
      id="stack"
      data-reveal="terminal"
      className={`relative z-10 mx-auto w-full max-w-6xl px-6 pb-28 pt-8 ${reveal("terminal")}`}
      aria-labelledby="stack-title"
    >
      <div className="grid items-center gap-14 lg:grid-cols-[1.1fr_0.9fr]">
        {/* Consola */}
        <div className="lp-reveal">
          <div className="relative overflow-hidden rounded-2xl border border-line-strong shadow-[0_28px_90px_rgba(0,0,0,0.5)]">
            {/* Halo tras la terminal */}
            <div
              aria-hidden="true"
              className="pointer-events-none absolute -inset-8 -z-10 rounded-[32px] opacity-60 blur-3xl"
              style={{
                background:
                  "radial-gradient(ellipse at 20% 0%, var(--lp-mesh-a), transparent 55%), radial-gradient(ellipse at 90% 100%, var(--lp-mesh-b), transparent 55%)",
              }}
            />

            <div className="flex items-center gap-2 border-b border-line bg-surface-2 px-4 py-3 backdrop-blur-md">
              <span className="h-2.5 w-2.5 rounded-full bg-[#1d4ed8]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#2563eb]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#3b82f6]" />
              <span className="ml-3 font-mono text-[10px] tracking-wider text-ink-faint">
                arca@zk: ~/stack — zsh
              </span>
            </div>

            <div
              className="relative overflow-x-auto bg-[var(--lp-terminal-bg)] px-5 py-6 font-mono text-[12px] leading-[1.9] backdrop-blur-xl sm:text-[13px]"
              role="log"
              aria-label="Salida de la terminal con el stack tecnológico"
            >
              {/* Scanlines */}
              <div
                aria-hidden="true"
                className="bg-scanlines pointer-events-none absolute inset-0 opacity-50"
              />
              <div className="relative min-w-max">
                {stackLines.map((line, i) => (
                  <span
                    key={line.text}
                    className={`lp-term-line ${KIND_CLASS[line.kind]}`}
                    style={{ ["--i" as string]: i, ["--chars" as string]: line.text.length }}
                  >
                    {line.text}
                  </span>
                ))}
                <span
                  className="lp-term-line text-blue-electric"
                  style={{ ["--i" as string]: stackLines.length, ["--chars" as string]: 2 }}
                >
                  $ <span className="animate-blink ml-0.5 inline-block h-[1em] w-[0.55em] translate-y-[0.12em] bg-blue-electric" />
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* CTA final */}
        <div className="lp-reveal" style={{ transitionDelay: "200ms" }}>
          <p className="mb-3 font-mono text-[11px] font-bold uppercase tracking-[0.28em] text-blue-electric">
          stack verificable
          </p>
          <h2
            id="stack-title"
            className="font-display text-[clamp(34px,4.5vw,52px)] font-semibold leading-[1.04] tracking-[-0.04em] text-ink"
          >
            Sin magia.
            <br />
            <span className="text-blue-electric">Solo matemática</span> que
            <br />
            puedes auditar.
          </h2>
          <p className="mt-5 max-w-md text-[15px] leading-relaxed text-ink-dim">
             // Abre DevTools: no verás contraseñas ni claves viajando. Solo IVs,
            nonces y ciphertext autenticado. Eso es Arca.
          </p>

          <div className="mt-9 flex flex-wrap items-center gap-5">
            <GlowCta onClick={onAccess}>Empezar en silencio</GlowCta>
            <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-ink-faint">
            </span>
          </div>

          <ul className="mt-10 grid gap-2.5 border-t border-line pt-6 font-mono text-[11px] text-ink-dim">
            {[
              "auditado con vectores NIST (PBKDF2 · AES-GCM)",
              "rate-limit 5 intentos / 15 min",
              "CSP estricta · CORS restringido",
            ].map((item) => (
              <li key={item} className="flex items-start gap-2.5">
                <span className="mt-[3px] text-blue-soft" aria-hidden="true">
                  ▸
                </span>
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
