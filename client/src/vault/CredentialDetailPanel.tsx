import { useState, type ReactNode } from "react";
import type { DecryptedCredential } from "../vault";
import { estimateEntropy } from "./StrengthMatrix";
import { CopyButton } from "./CopyButton";
import { ScrambleText } from "./ScrambleText";
import { TotpBlock } from "./TotpBlock";
import { getFaviconUrl } from "./CredentialCard";
import { analyzeUrl } from "../anti-phishing";

interface CredentialDetailPanelProps {
  credential: DecryptedCredential | null;
  onEdit: (id: number | string) => void;
  onDelete: (id: number | string) => void;
  breachedIds: Set<number | string>;
  busy: boolean;
}

function FieldLabel({ children }: { children: ReactNode }) {
  return (
    <span className="mb-1.5 block font-mono text-[14px] uppercase tracking-[0.2em] text-ink-faint">
      {children}
    </span>
  );
}

function AuditBlock({
  credential,
  isBreached,
}: {
  credential: DecryptedCredential;
  isBreached: boolean;
}) {
  const entropy = estimateEntropy(credential.password);
  const healthy = credential.password.length >= 10 && entropy >= 50;
  const bar = Math.min(entropy / 100, 1);

  return (
    <div className="rounded-xl border border-line bg-vault-glass p-4 backdrop-blur-md">
      <div className="mb-3 flex items-center gap-2 font-mono text-[15px] uppercase tracking-[0.18em] text-ink-dim">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-vault-accent">
          <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
        </svg>
        <span>Auditoría</span>
      </div>

      <div className="space-y-3">
        <div>
          <div className="flex items-baseline justify-between">
            <span className="font-mono text-[14px] uppercase tracking-wider text-ink-faint">
              Entropía
            </span>
            <span
              className={`font-mono text-lg tabular-nums ${healthy ? "text-vault-ok" : "text-vault-warn"}`}
            >
              {Math.round(entropy)} bits
            </span>
          </div>
          <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-vault-track">
            <span
              className={`block h-full origin-left transition-transform duration-500 ${
                healthy ? "bg-lime-600 [data-theme=dark]:bg-lime-300" : "bg-amber-500 [data-theme=dark]:bg-amber-400"
              }`}
              style={{ width: "100%", transform: `scaleX(${bar})` }}
            />
          </div>
          <p className="mt-1 font-mono text-[14px] uppercase tracking-wider text-ink-faint">
            {healthy ? "Saludable" : "Débil"}
          </p>
        </div>

        <div className="border-t border-line/50 pt-3">
          <div className="flex items-baseline justify-between">
            <span className="font-mono text-[14px] uppercase tracking-wider text-ink-faint">
              HIBP
            </span>
            <span
              className={`font-mono text-base ${isBreached ? "text-vault-danger" : "text-vault-ok"}`}
            >
              {isBreached ? "COMPROMETIDA" : "NO ENCONTRADA"}
            </span>
          </div>
          {isBreached && (
            <p className="mt-2 rounded border border-red-500/40 bg-vault-danger-soft px-2 py-1.5 font-mono text-[14px] leading-relaxed text-vault-danger">
              Aparece en filtraciones conocidas. Cámbiala inmediatamente.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export function CredentialDetailPanel({
  credential,
  onEdit,
  onDelete,
  breachedIds,
  busy,
}: CredentialDetailPanelProps) {
  const [revealed, setRevealed] = useState(false);
  const [revealKey, setRevealKey] = useState(0);

  if (!credential) {
    return (
      <section
        className="relative flex h-full min-h-0 flex-col items-center justify-center overflow-hidden p-8 text-center"
        aria-label="Detalle de credencial"
      >
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(37,99,235,0.08),transparent_70%)]"
        />
        <div className="relative z-10 flex flex-col items-center gap-3">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-line bg-vault-glass text-vault-accent backdrop-blur-md shadow-[0_0_40px_rgba(37,99,235,0.1)]">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              <circle cx="12" cy="16" r="1" />
            </svg>
          </div>
          <p className="font-mono text-[15px] uppercase tracking-[0.24em] text-vault-accent">
            // esperando selección
          </p>
          <h3 className="font-display text-2xl text-ink">Selecciona una credencial</h3>
          <p className="max-w-[24ch] text-lg text-ink-dim">
            para ver sus detalles desencriptados en RAM
          </p>
        </div>
      </section>
    );
  }

  const firstUrl = credential.urls.find((u) => u.length > 0);
  const faviconUrl = firstUrl ? getFaviconUrl(firstUrl) : null;
  const isBreached = breachedIds.has(credential.id);
  const activeUrls = credential.urls.filter((u) => u.length > 0);

  function toggleReveal() {
    setRevealed((v) => {
      if (!v) setRevealKey((k) => k + 1);
      return !v;
    });
  }

  return (
    <section
      className="relative h-full min-h-0 overflow-y-auto"
      aria-label="Detalle de credencial"
    >
      <div
        aria-hidden
        className="pointer-events-none sticky top-0 z-0 h-0"
      >
        <div className="pointer-events-none absolute -inset-x-8 top-0 h-[280px] bg-[radial-gradient(ellipse_at_top,rgba(37,99,235,0.14),transparent_70%)]" />
      </div>

      <div className="relative z-10 space-y-4 p-4 lg:p-5">
        <header className="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-line bg-vault-glass p-4 backdrop-blur-md">
          <div className="flex min-w-0 items-center gap-3">
            <div className="relative flex h-12 w-12 shrink-0 items-center justify-center overflow-hidden rounded-xl border border-line bg-vault-soft-2">
              {faviconUrl ? (
                <img
                  src={faviconUrl}
                  alt=""
                  width={28}
                  height={28}
                  className="h-7 w-7"
                  onError={(e) => {
                    (e.currentTarget as HTMLImageElement).style.display = "none";
                  }}
                />
              ) : null}
              <span
                className={`absolute inset-0 flex items-center justify-center font-display text-2xl font-semibold text-vault-accent ${
                  faviconUrl ? "opacity-0" : "opacity-100"
                }`}
              >
                {credential.title.charAt(0).toUpperCase()}
              </span>
            </div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="truncate font-display text-3xl font-semibold text-ink">
                  {credential.title}
                </h2>
                {isBreached && (
                  <span className="rounded border border-red-500/50 bg-vault-danger-soft px-1.5 py-0.5 font-mono text-[13px] uppercase tracking-wider text-vault-danger">
                    comprometida
                  </span>
                )}
                {credential.favorite && (
                  <span className="rounded border border-amber-500/50 bg-vault-warn-soft px-1.5 py-0.5 font-mono text-[13px] uppercase tracking-wider text-vault-warn">
                    ★ fav
                  </span>
                )}
              </div>
              <p className="mt-0.5 truncate font-mono text-[15px] text-ink-faint">
                {credential.username}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              type="button"
              onClick={() => onEdit(credential.id)}
              className="rounded-lg border border-line bg-vault-soft-2 px-3 py-1.5 font-mono text-[15px] uppercase tracking-wider text-ink-dim transition-all hover:border-blue-500/50 hover:text-vault-accent"
            >
              Editar
            </button>
            <button
              type="button"
              onClick={() => onDelete(credential.id)}
              disabled={busy}
              className="rounded-lg border border-red-500/50 bg-vault-danger-soft px-3 py-1.5 font-mono text-[15px] uppercase tracking-wider text-vault-danger transition-all hover:border-red-500/70 disabled:opacity-50"
            >
              Eliminar
            </button>
          </div>
        </header>

        <div className="grid gap-4 xl:grid-cols-1">
          <div className="space-y-4 rounded-xl border border-line bg-vault-glass p-4 backdrop-blur-md">
            <div>
              <FieldLabel>Usuario</FieldLabel>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={credential.username}
                  readOnly
                  aria-label="Nombre de usuario"
                    className="min-w-0 flex-1 rounded-lg border border-line bg-vault-input px-3 py-2.5 font-mono text-lg text-ink outline-none transition focus:border-blue-500/50"
                />
                <CopyButton value={credential.username} label="Copiar" />
              </div>
            </div>

            <div>
              <FieldLabel>Contraseña</FieldLabel>
              <div className="flex flex-wrap items-center gap-2">
                {revealed ? (
                  <div
                    aria-label="Contraseña revelada"
                    className="min-w-0 flex-1 overflow-hidden rounded-lg border border-blue-500/50 bg-vault-input px-3 py-2.5 font-mono text-lg text-ink shadow-[0_0_20px_rgba(37,99,235,0.12)] [data-theme=dark]:text-blue-100"
                  >
                    <ScrambleText
                      value={credential.password}
                      trigger={revealKey}
                    />
                  </div>
                ) : (
                  <input
                    type="password"
                    value={credential.password}
                    readOnly
                    aria-label="Contraseña"
                  className="min-w-0 flex-1 rounded-lg border border-line bg-vault-input px-3 py-2.5 font-mono text-lg text-ink outline-none transition focus:border-blue-500/50"
                  />
                )}
                <button
                  type="button"
                  onClick={toggleReveal}
                  title={revealed ? "Ocultar contraseña" : "Revelar contraseña (descifrar)"}
                  aria-label={revealed ? "Ocultar contraseña" : "Mostrar contraseña"}
                  aria-pressed={revealed}
                  className={`flex h-[38px] w-[38px] shrink-0 items-center justify-center rounded-lg border transition-all duration-150 ${
                    revealed
                      ? "border-blue-500/60 bg-vault-accent-soft text-vault-accent shadow-[0_0_16px_rgba(37,99,235,0.25)]"
                      : "border-line bg-vault-soft-2 text-ink-dim hover:border-blue-500/50 hover:text-vault-accent"
                  }`}
                >
                  {revealed ? (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                      <line x1="1" y1="1" x2="23" y2="23" />
                    </svg>
                  ) : (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
                <CopyButton value={credential.password} label="Copiar" />
              </div>
              {revealed && (
                <p
                  aria-live="polite"
                  className="mt-1.5 font-mono text-[14px] uppercase tracking-[0.14em] text-vault-accent"
                >
                  ▸ AES-GCM decrypt · RAM only
                </p>
              )}
            </div>

            {activeUrls.length > 0 && (
              <div>
                <FieldLabel>URLs</FieldLabel>
                <div className="space-y-2">
                  {activeUrls.map((url, index) => {
                    const report = analyzeUrl(url);
                    return (
                      <div key={index} className="space-y-1">
                        <a
                          href={url}
                          target="_blank"
                          rel="noreferrer"
                          className="block truncate rounded-lg border border-line bg-vault-input px-3 py-2 font-mono text-base text-vault-accent transition-all hover:border-blue-500/50 hover:bg-vault-accent-softer hover:shadow-[0_0_16px_rgba(37,99,235,0.12)]"
                        >
                          {url}
                        </a>
                        {report && report.riskLevel === "danger" && (
                          <div className="rounded-lg border border-red-500/50 bg-red-950/20 px-3 py-1.5 font-mono text-xs text-red-400">
                            <strong>{report.typosquatTarget ? `Posible imitación de ${report.typosquatTarget}` : report.threatTitle}:</strong> {report.threatDescription || "Esta dirección es riesgosa o fraudulenta."}
                          </div>
                        )}
                        {report && report.riskLevel === "warning" && (
                          <div className="rounded-lg border border-amber-500/50 bg-amber-950/20 px-3 py-1.5 font-mono text-xs text-amber-400">
                            <strong>HTTP no seguro:</strong> Conexión no cifrada vulnerable a intercepción.
                          </div>
                        )}
                        {report && report.riskLevel === "safe" && report.isOfficialVerified && (
                          <div className="font-mono text-[13px] text-emerald-400">
                            ✓ Servicio oficial verificado ({report.hostname})
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          <div className="space-y-4">
            {credential.totpSecret && <TotpBlock secret={credential.totpSecret} />}
            <AuditBlock credential={credential} isBreached={isBreached} />
          </div>
        </div>
      </div>
    </section>
  );
}
