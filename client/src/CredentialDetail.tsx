import { useState, useEffect } from "react";
import type { DecryptedCredential } from "./vault";
import { getTotpSnapshot } from "./totp";
import { auditVault } from "./vault-health";

interface CredentialDetailProps {
  credential: DecryptedCredential | null;
  onEdit: (id: number | string) => void;
  onDelete: (id: number | string) => void;
  breachedIds: Set<number | string>;
  busy: boolean;
}

function getFaviconUrl(url: string): string | null {
  try {
    const { hostname } = new URL(url);
    if (!hostname) return null;
    return `https://www.google.com/s2/favicons?domain=${hostname}&sz=64`;
  } catch {
    return null;
  }
}

async function copyToClipboard(text: string): Promise<boolean> {
  if (!navigator.clipboard) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function estimateEntropy(password: string): number {
  const alphabetSize = new Set(password).size;
  return password.length * Math.log2(alphabetSize || 1);
}

function TotpDetail({ secret }: { secret: string }) {
  const [snapshot, setSnapshot] = useState<ReturnType<typeof getTotpSnapshot> | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let active = true;

    function refresh() {
      try {
        const nextSnapshot = getTotpSnapshot(secret);
        if (active) {
          setSnapshot(nextSnapshot);
          setError("");
          setCopied(false);
        }
      } catch {
        if (active) setError("No se pudo calcular el código TOTP");
      }
    }

    refresh();
    const intervalId = window.setInterval(refresh, 1000);
    return () => {
      active = false;
      window.clearInterval(intervalId);
    };
  }, [secret]);

  async function copyCode() {
    if (!snapshot || !navigator.clipboard) {
      setError("El navegador no permite copiar el código");
      return;
    }
    try {
      await navigator.clipboard.writeText(snapshot.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("No se pudo copiar el código");
    }
  }

  if (error) return <div className="detail-totp-error">{error}</div>;
  if (!snapshot) return <div className="detail-totp-loading">Calculando código...</div>;

  const isCritical = snapshot.remainingSeconds <= 5;

  return (
    <div className={`detail-totp-card ${isCritical ? "detail-totp-critical" : ""}`}>
      <div className="detail-totp-header">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <span>Código 2FA</span>
        <span className="detail-totp-timer">{snapshot.remainingSeconds}s</span>
      </div>
      <output className="detail-totp-code" aria-live="polite" aria-label="Código TOTP">
        {snapshot.code}
      </output>
      <div className="detail-totp-progress" role="progressbar" aria-label="Tiempo restante" aria-valuemin={0} aria-valuemax={30} aria-valuenow={snapshot.remainingSeconds}>
        <span style={{ transform: `scaleX(${snapshot.progress})` }} />
      </div>
      <button className="detail-totp-copy" type="button" onClick={copyCode}>
        {copied ? "Copiado" : "Copiar código"}
      </button>
    </div>
  );
}

function AuditDetail({ credential, isBreached }: { credential: DecryptedCredential; isBreached: boolean }) {
  const entropy = estimateEntropy(credential.password);
  const isHealthy = credential.password.length >= 10 && entropy >= 50;

  return (
    <div className="detail-audit-card">
      <div className="detail-audit-header">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
        </svg>
        <span>Auditoría</span>
      </div>

      <div className="detail-audit-item">
        <span className="detail-audit-label">Entropía</span>
        <div className="detail-audit-value-row">
          <span className={`detail-audit-value ${entropy >= 50 ? "detail-audit-safe" : "detail-audit-warn"}`}>
            {Math.round(entropy)} bits
          </span>
          <span className="detail-audit-status">{isHealthy ? "Saludable" : "Débil"}</span>
        </div>
        <div className="detail-audit-bar">
          <span style={{ transform: `scaleX(${Math.min(entropy / 100, 1)})` }} className={entropy >= 50 ? "detail-audit-bar-fill--safe" : "detail-audit-bar-fill--warn"} />
        </div>
      </div>

      <div className="detail-audit-item">
        <span className="detail-audit-label">Brechas HIBP</span>
        <div className="detail-audit-value-row">
          <span className={`detail-audit-value ${isBreached ? "detail-audit-danger" : "detail-audit-safe"}`}>
            {isBreached ? "Comprometida" : "No encontrada"}
          </span>
        </div>
        {isBreached && (
          <p className="detail-audit-warning">
            Esta contraseña aparece en filtraciones conocidas. Cámbiala inmediatamente.
          </p>
        )}
      </div>
    </div>
  );
}

export function CredentialDetail({
  credential,
  onEdit,
  onDelete,
  breachedIds,
  busy,
}: CredentialDetailProps) {
  const [revealedPassword, setRevealedPassword] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  if (!credential) {
    return (
      <div className="detail-empty-state">
        <div className="detail-empty-icon">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            <circle cx="12" cy="16" r="1"/>
          </svg>
        </div>
        <h3>Selecciona una credencial</h3>
        <p>para ver sus detalles</p>
      </div>
    );
  }

  const firstUrl = credential.urls.find((u) => u.length > 0);
  const faviconUrl = firstUrl ? getFaviconUrl(firstUrl) : null;
  const isBreached = breachedIds.has(credential.id);

  async function handleCopy(text: string, field: string) {
    if (await copyToClipboard(text)) {
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    }
  }

  return (
    <div className="detail-container">
      <div className="detail-header">
        <div className="detail-header-left">
          <div className="detail-logo">
            {faviconUrl ? (
              <img
                className="detail-logo-img"
                src={faviconUrl}
                alt=""
                width="48"
                height="48"
                onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = "none"; }}
              />
            ) : null}
            <span className={`detail-logo-fallback ${faviconUrl ? "detail-logo-fallback--hidden" : ""}`}>
              {credential.title.charAt(0).toUpperCase()}
            </span>
          </div>
          <div className="detail-title-group">
            <h2 className="detail-title">{credential.title}</h2>
            {isBreached && <span className="detail-badge detail-badge--breach">Comprometida</span>}
          </div>
        </div>
        <div className="detail-actions">
          <button
            className="detail-action-button"
            type="button"
            onClick={() => onEdit(credential.id)}
            title="Editar credencial"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
              <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
            </svg>
            Editar
          </button>
          <button
            className="detail-action-button detail-action-button--danger"
            type="button"
            onClick={() => onDelete(credential.id)}
            disabled={busy}
            title="Eliminar credencial"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="3 6 5 6 21 6"/>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
            </svg>
            Eliminar
          </button>
        </div>
      </div>

      <div className="detail-grid">
        <div className="detail-column">
          <div className="detail-field">
            <label className="detail-label">Usuario</label>
            <div className="detail-input-row">
              <input
                className="detail-input"
                type="text"
                value={credential.username}
                readOnly
                aria-label="Nombre de usuario"
              />
              <button
                className="detail-copy-button"
                type="button"
                onClick={() => handleCopy(credential.username, "username")}
                title="Copiar usuario"
              >
                {copiedField === "username" ? "Copiado" : "Copiar"}
              </button>
            </div>
          </div>

          <div className="detail-field">
            <label className="detail-label">Contraseña</label>
            <div className="detail-input-row">
              <input
                className="detail-input detail-input--password"
                type={revealedPassword ? "text" : "password"}
                value={credential.password}
                readOnly
                aria-label="Contraseña"
              />
              <button
                className="detail-icon-button"
                type="button"
                onClick={() => setRevealedPassword(!revealedPassword)}
                title={revealedPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
              >
                {revealedPassword ? (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
                    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
                    <line x1="1" y1="1" x2="23" y2="23"/>
                  </svg>
                ) : (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                    <circle cx="12" cy="12" r="3"/>
                  </svg>
                )}
              </button>
              <button
                className="detail-copy-button"
                type="button"
                onClick={() => handleCopy(credential.password, "password")}
                title="Copiar contraseña"
              >
                {copiedField === "password" ? "Copiado" : "Copiar"}
              </button>
            </div>
          </div>

          {credential.urls.filter(u => u.length > 0).length > 0 && (
            <div className="detail-field">
              <label className="detail-label">URLs</label>
              <div className="detail-urls">
                {credential.urls.filter(u => u.length > 0).map((url, index) => (
                  <a
                    key={index}
                    className="detail-url"
                    href={url}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {url}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="detail-column">
          {credential.totpSecret && <TotpDetail secret={credential.totpSecret} />}
          <AuditDetail credential={credential} isBreached={isBreached} />
        </div>
      </div>
    </div>
  );
}
