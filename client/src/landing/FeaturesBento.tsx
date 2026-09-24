type FeaturesBentoProps = {
  reveal: (id: string) => string;
};

type Pillar = {
  id: string;
  index: string;
  title: string;
  body: string;
  metric: string;
  metricLabel: string;
  span: string;
  delay: string;
  icon: React.ReactNode;
  accent: "electric" | "soft" | "deep";
  extra?: { label: string; value: string }[];
};

const ICON_CLASS = {
  electric: "border-blue-electric/40 bg-blue-electric/10 text-blue-electric",
  soft: "border-blue-soft/40 bg-blue-soft/10 text-blue-soft",
  deep: "border-blue-deep/50 bg-blue-deep/15 text-blue-deep",
} as const;

const pillars: Pillar[] = [
  {
    id: "zk",
    index: "01",
    title: "Zero-Knowledge · RAM Volatility",
    body: "Tu contraseña maestra deriva la Master Key en la RAM del navegador y nunca se persiste. Al cerrar la pestaña, el material clave se evapora: el servidor solo conoce un authHash bcrypt que no revela nada.",
    metric: "600 000",
    metricLabel: "iteraciones PBKDF2-SHA256",
    span: "sm:col-span-2 lg:col-span-4 lg:row-span-2",
    delay: "0ms",
    accent: "electric",
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83" />
        <circle cx="12" cy="12" r="4" />
      </svg>
    ),
    extra: [
      { label: "clave viva solo en", value: "RAM" },
      { label: "persistencia de secreto", value: "0 bytes" },
      { label: "split-key", value: "HKDF-SHA256" },
    ],
  },
  {
    id: "aes",
    index: "02",
    title: "Cifrado local AES-GCM",
    body: "Cada credencial se cifra en tu dispositivo con Web Crypto API antes de tocar la red. IV único de 12 bytes por operación; el ciphertext sale autenticado e ilegible.",
    metric: "AES-256-GCM",
    metricLabel: "IV 12B · Web Crypto API",
    span: "sm:col-span-2 lg:col-span-2",
    delay: "80ms",
    accent: "soft",
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <rect x="3" y="11" width="18" height="11" rx="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        <circle cx="12" cy="16" r="1" />
      </svg>
    ),
  },
  {
    id: "kanon",
    index: "03",
    title: "k-Anonymity · HIBP",
    body: "Al auditar brechas calculamos SHA-1 localmente y solo enviamos el prefijo de 5 caracteres. Have I Been Pwned nunca recibe tu contraseña completa.",
    metric: "5 chars",
    metricLabel: "prefijo SHA-1 · nunca el hash entero",
    span: "sm:col-span-2 lg:col-span-2",
    delay: "160ms",
    accent: "deep",
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
        <circle cx="12" cy="12" r="3" />
        <line x1="2" y1="2" x2="22" y2="22" />
      </svg>
    ),
  },
  {
    id: "vaultkey",
    index: "04",
    title: "Vault Key envuelta",
    body: "La clave de bóveda se genera una vez y viaja siempre envuelta por la Master Key. Cambiar tu maestra re-envuelve sin re-cifrar tus datos.",
    metric: "256 bits",
    metricLabel: "wrapped · nunca en claro",
    span: "sm:col-span-1 lg:col-span-3",
    delay: "240ms",
    accent: "electric",
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
      </svg>
    ),
  },
  {
    id: "session",
    index: "05",
    title: "Sesión endurecida",
    body: "Rate-limit agresivo y CSP estricta vía Helmet. El perímetro reacciona como una caja fuerte.",
    metric: "8 h",
    metricLabel: "cookie httpOnly · rate-limit 5/15min",
    span: "sm:col-span-1 lg:col-span-3",
    delay: "320ms",
    accent: "soft",
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    ),
  },
];

export function FeaturesBento({ reveal }: FeaturesBentoProps) {
  return (
    <section
      id="arquitectura"
      data-reveal="bento"
      aria-labelledby="bento-title"
      className="relative z-10 mx-auto w-full max-w-6xl px-6 py-28"
    >
      {/* Scanlines de terminal sobre la sección */}
      <div
        aria-hidden="true"
        className="bg-scanlines pointer-events-none absolute inset-x-0 top-0 h-40 opacity-40 [mask-image:linear-gradient(to_bottom,black,transparent)]"
      />

      <div className={`lp-reveal relative mb-12 max-w-2xl ${reveal("bento")}`}>
        <p className="mb-3 font-mono text-[11px] font-bold uppercase tracking-[0.28em] text-blue-electric">
          La arquitectura · 03 pilares
        </p>
        <h2
          id="bento-title"
          className="font-display text-[clamp(36px,5vw,56px)] font-semibold leading-[1.02] tracking-[-0.04em] text-ink"
        >
          Diseñada para que{" "}
          <span className="text-blue-electric">incluso nosotros</span> no podamos leerte.
        </h2>
        <p className="mt-4 max-w-lg text-[15px] leading-relaxed text-ink-dim">
          // Cada capa del sistema asume un backend hostil. Lo que viaja por la red es
          ruido cifrado; las claves viven solo en tu dispositivo.
        </p>
      </div>

      <div className="relative grid auto-rows-min grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-6">
        {pillars.map((p) => (
          <article
            key={p.id}
            data-reveal={`card-${p.id}`}
            className={`lp-reveal ${reveal(`card-${p.id}`)} group relative overflow-hidden rounded-2xl border border-line bg-surface p-7 backdrop-blur-md transition-all duration-300 hover:-translate-y-1 hover:border-glow hover:shadow-[0_0_36px_var(--lp-glow)] ${p.span}`}
            style={{ transitionDelay: p.delay }}
          >
            {/* Glow interior en hover */}
            <div
              aria-hidden="true"
              className="pointer-events-none absolute -right-12 -top-12 h-40 w-40 rounded-full opacity-0 blur-2xl transition-opacity duration-500 group-hover:opacity-100"
              style={{
                background:
                  p.accent === "soft"
                    ? "radial-gradient(circle, rgba(96,165,250,0.35), transparent 65%)"
                    : p.accent === "deep"
                      ? "radial-gradient(circle, rgba(59,130,246,0.4), transparent 65%)"
                      : "radial-gradient(circle, rgba(37,99,235,0.4), transparent 65%)",
              }}
            />

            <div className="relative flex items-start justify-between gap-4">
              <div
                className={`grid h-12 w-12 place-items-center rounded-xl border transition-shadow duration-300 group-hover:shadow-[0_0_18px_var(--lp-glow)] ${ICON_CLASS[p.accent]}`}
              >
                {p.icon}
              </div>
              <span className="font-mono text-[11px] font-bold tracking-[0.16em] text-ink-faint">
                {p.index}
              </span>
            </div>

            <h3 className="relative mt-5 font-display text-[19px] font-semibold leading-snug tracking-tight text-ink">
              {p.title}
            </h3>
            <p className="relative mt-2.5 text-[13.5px] leading-relaxed text-ink-dim">
              {p.body}
            </p>

            <div className="relative mt-6 border-t border-line pt-4">
              <p
                className={`font-mono text-lg font-bold tracking-tight ${
                  p.accent === "soft" ? "text-blue-soft" : p.accent === "deep" ? "text-blue-deep" : "text-blue-electric"
                }`}
              >
                {p.metric}
              </p>
              <p className="mt-0.5 font-mono text-[10px] uppercase tracking-[0.14em] text-ink-faint">
                {p.metricLabel}
              </p>
            </div>

            {p.extra && (
              <dl className="relative mt-5 grid grid-cols-3 gap-3 border-t border-line pt-4">
                {p.extra.map((x) => (
                  <div key={x.label}>
                    <dt className="font-mono text-[9px] uppercase tracking-[0.1em] text-ink-faint">
                      {x.label}
                    </dt>
                    <dd className="mt-1 font-mono text-[12px] font-bold text-ink">{x.value}</dd>
                  </div>
                ))}
              </dl>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}
