import { useEffect, useState } from "react";
import { getTotpSnapshot, TOTP_PERIOD_SECONDS } from "../totp";
import { CopyButton } from "./CopyButton";
import { ScrambleText } from "./ScrambleText";

interface TotpBlockProps {
  secret: string;
}

/** Bloque TOTP monospace con barra de validez cyan de 30s. */
export function TotpBlock({ secret }: TotpBlockProps) {
  const [snapshot, setSnapshot] = useState<ReturnType<typeof getTotpSnapshot> | null>(null);
  const [error, setError] = useState("");
  const [scrambleKey, setScrambleKey] = useState(0);

  useEffect(() => {
    let active = true;

    function refresh() {
      try {
        const next = getTotpSnapshot(secret);
        if (!active) return;
        setSnapshot((prev) => {
          if (!prev || prev.code !== next.code) setScrambleKey((k) => k + 1);
          return next;
        });
        setError("");
      } catch {
        if (active) setError("No se pudo calcular el código TOTP");
      }
    }

    refresh();
    const id = window.setInterval(refresh, 1000);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [secret]);

  if (error) {
    return (
      <div className="rounded-xl border border-fuchsia-500/50 bg-vault-fuchsia-soft p-4 font-mono text-base text-vault-fuchsia">
        {error}
      </div>
    );
  }

  if (!snapshot) {
    return (
      <div className="rounded-xl border border-line bg-vault-glass p-4 font-mono text-base text-ink-faint backdrop-blur-md">
        Calculando código...
      </div>
    );
  }

  const critical = snapshot.remainingSeconds <= 5;
  const displayCode = snapshot.code.slice(0, 3) + " " + snapshot.code.slice(3);

  return (
    <div
      className={`relative overflow-hidden rounded-xl border backdrop-blur-md transition-colors duration-200 ${
        critical
          ? "border-fuchsia-500/60 bg-vault-fuchsia-soft shadow-[0_0_24px_rgba(217,70,239,0.2)]"
          : "border-cyan-500/40 bg-vault-glass shadow-[0_0_24px_rgba(6,182,212,0.08)]"
      }`}
      aria-label="Código de autenticación de dos factores"
    >
      <div
          className="pointer-events-none absolute inset-0 opacity-25 bg-scanlines"
        aria-hidden
      />
      <div className="relative flex items-center justify-between gap-3 border-b border-line/60 px-4 py-2.5">
        <div className="flex items-center gap-2 font-mono text-[15px] uppercase tracking-[0.18em] text-ink-dim">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className={critical ? "text-vault-fuchsia" : "text-vault-accent"}>
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <span>2FA · TOTP</span>
        </div>
        <span
          className={`font-mono text-[15px] tabular-nums tracking-wider ${
            critical ? "text-vault-fuchsia animate-pulse" : "text-vault-accent"
          }`}
        >
          {snapshot.remainingSeconds}s
        </span>
      </div>
      <div className="relative flex items-center justify-between gap-3 px-4 py-4">
        <output
          className="font-mono text-4xl font-semibold tracking-[0.35em] text-ink"
          aria-live="polite"
          aria-label="Código TOTP"
        >
          <ScrambleText value={displayCode} trigger={scrambleKey} durationMs={320} />
        </output>
        <CopyButton value={snapshot.code} label="Copiar" />
      </div>
      <div
        className="relative h-0.5 bg-vault-track"
        role="progressbar"
        aria-label="Tiempo restante"
        aria-valuemin={0}
        aria-valuemax={TOTP_PERIOD_SECONDS}
        aria-valuenow={snapshot.remainingSeconds}
      >
        <span
          className={`absolute inset-y-0 left-0 origin-left transition-transform duration-200 ease-linear ${
            critical ? "bg-fuchsia-400" : "bg-cyan-600 [data-theme=dark]:bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]"
          }`}
          style={{ width: "100%", transform: `scaleX(${snapshot.progress})` }}
        />
      </div>
    </div>
  );
}
