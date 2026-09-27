import { FormEvent, useEffect, useState } from "react";
import QRCode from "qrcode";
import { disableMfa, enableMfa, getMfaStatus, setupMfa } from "./api";
import { validateMfaCode } from "./validation";

interface MfaSetupInfo {
  secret: string;
  otpauthUri: string;
  qrDataUrl: string;
}

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

async function writeClipboard(text: string): Promise<boolean> {
  if (!navigator.clipboard) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * Sección "Verificación en dos pasos" dentro de Mi Cuenta.
 * Gestiona el ciclo completo: consultar estado, alta con QR + confirmación,
 * entrega única de códigos de respaldo y desactivación con segundo factor.
 */
export function MfaSettings() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [loadError, setLoadError] = useState("");
  const [setupInfo, setSetupInfo] = useState<MfaSetupInfo | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [showDisable, setShowDisable] = useState(false);
  const [copiedField, setCopiedField] = useState<"" | "secret" | "codes">("");

  useEffect(() => {
    let cancelled = false;
    getMfaStatus()
      .then((status) => {
        if (!cancelled) setEnabled(status.enabled);
      })
      .catch(() => {
        if (!cancelled) {
          setLoadError("No se pudo comprobar el estado de la verificación en dos pasos.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleStartSetup() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const setup = await setupMfa();
      const qrDataUrl = await QRCode.toDataURL(setup.otpauthUri, { margin: 1, width: 220 });
      setSetupInfo({ secret: setup.secret, otpauthUri: setup.otpauthUri, qrDataUrl });
      setCode("");
    } catch (setupError) {
      setError(errorMessage(setupError, "No se pudo preparar la configuración del MFA"));
    } finally {
      setBusy(false);
    }
  }

  async function handleEnable(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const codeError = validateMfaCode(code);
    if (codeError) {
      setError(codeError);
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await enableMfa({ code: code.trim() });
      // Los códigos de respaldo solo se muestran aquí: el servidor no los vuelve a entregar.
      setBackupCodes(result.backupCodes);
      setSetupInfo(null);
      setEnabled(true);
      setCode("");
    } catch (enableError) {
      setError(errorMessage(enableError, "No se pudo activar la verificación en dos pasos"));
    } finally {
      setBusy(false);
    }
  }

  async function handleDisable(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const codeError = validateMfaCode(code);
    if (codeError) {
      setError(codeError);
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await disableMfa({ code: code.trim() });
      setEnabled(false);
      setShowDisable(false);
      setCode("");
      setNotice("Verificación en dos pasos desactivada.");
    } catch (disableError) {
      setError(errorMessage(disableError, "No se pudo desactivar la verificación en dos pasos"));
    } finally {
      setBusy(false);
    }
  }

  async function handleCopy(text: string, field: "secret" | "codes") {
    const copied = await writeClipboard(text);
    if (!copied) {
      setError("No se pudo copiar al portapapeles");
      return;
    }
    setCopiedField(field);
    window.setTimeout(() => setCopiedField(""), 1600);
  }

  function handleDownloadBackups() {
    if (!backupCodes) return;
    const contents = `Codigos de respaldo de Arca\n\n${backupCodes.join("\n")}\n`;
    const url = URL.createObjectURL(new Blob([contents], { type: "text/plain;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "arca-codigos-respaldo.txt";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function handleAcknowledgeBackups() {
    setBackupCodes(null);
    setNotice("Verificación en dos pasos activada. Tu cuenta ya pide un segundo factor al iniciar sesión.");
  }

  function handleCancelSetup() {
    setSetupInfo(null);
    setCode("");
    setError("");
  }

  const enableInvalid = validateMfaCode(code.trim()) !== null;
  const disableInvalid = validateMfaCode(code.trim()) !== null;

  return (
    <div className="account-section mfa-section">
      <h3 className="account-section-title">
        Verificación en dos pasos{" "}
        {enabled === true && <span className="mfa-status-badge mfa-status-badge--on">Activa</span>}
        {enabled === false && <span className="mfa-status-badge">Desactivada</span>}
      </h3>

      {loadError && (
        <p className="feedback error" role="alert">
          {loadError}
        </p>
      )}
      {enabled === null && !loadError && (
        <p className="account-section-description">Comprobando el estado...</p>
      )}

      {enabled === false && !setupInfo && !backupCodes && (
        <>
          <p className="account-section-description">
            Añade un código de tu app de autenticación al iniciar sesión, además de
            la contraseña maestra. Si pierdes el dispositivo, los códigos de
            respaldo te permitirán seguir entrando.
          </p>
          <button className="primary-button" type="button" onClick={handleStartSetup} disabled={busy}>
            {busy ? "Preparando..." : "Activar verificación en dos pasos"}
          </button>
        </>
      )}

      {setupInfo && (
        <div className="mfa-setup">
          <ol className="mfa-instructions">
            <li>Abre tu app de autenticación (Google Authenticator, Aegis, 1Password...).</li>
            <li>Escanea este QR o introduce el secreto manualmente.</li>
            <li>Escribe el código de 6 dígitos que muestra la app.</li>
          </ol>
          <div className="mfa-qr-frame">
            <img
              className="mfa-qr"
              src={setupInfo.qrDataUrl}
              alt="Código QR del secreto TOTP para configurar Arca en tu app de autenticación"
            />
          </div>
          <div className="mfa-secret-box">
            <span className="mfa-secret-label">Secreto manual</span>
            <code className="mfa-secret-value">{setupInfo.secret}</code>
            <button
              className="secondary-button"
              type="button"
              onClick={() => handleCopy(setupInfo.secret, "secret")}
            >
              {copiedField === "secret" ? "Copiado" : "Copiar"}
            </button>
          </div>
          <form className="credential-form" onSubmit={handleEnable}>
            <label htmlFor="mfa-enable-code">Código de confirmación</label>
            <input
              id="mfa-enable-code"
              className="mfa-code-input"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="123456"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              required
            />
            <div className="form-actions">
              <button
                className="primary-button"
                type="submit"
                disabled={busy || enableInvalid}
              >
                {busy ? "Activando..." : "Confirmar y activar"}
              </button>
              <button
                className="secondary-button"
                type="button"
                onClick={handleCancelSetup}
                disabled={busy}
              >
                Cancelar
              </button>
            </div>
          </form>
        </div>
      )}

      {backupCodes && (
        <div className="mfa-backups">
          <p className="mfa-warning">
            Guarda ahora estos códigos de respaldo: solo se muestran una vez y
            permiten entrar si pierdes tu dispositivo.
          </p>
          <ul className="mfa-backup-list">
            {backupCodes.map((backupCode) => (
              <li key={backupCode}>
                <code>{backupCode}</code>
              </li>
            ))}
          </ul>
          <div className="form-actions">
            <button
              className="secondary-button"
              type="button"
              onClick={() => handleCopy(backupCodes.join("\n"), "codes")}
            >
              {copiedField === "codes" ? "Copiados" : "Copiar todos"}
            </button>
            <button className="secondary-button" type="button" onClick={handleDownloadBackups}>
              Descargar .txt
            </button>
            <button className="primary-button" type="button" onClick={handleAcknowledgeBackups}>
              He guardado mis códigos
            </button>
          </div>
        </div>
      )}

      {enabled === true && !backupCodes && (
        <>
          <p className="account-section-description">
            Tu cuenta pide además un código de 6 dígitos al iniciar sesión. Se
            recomienda mantenerla activa.
          </p>
          {showDisable ? (
            <form className="credential-form" onSubmit={handleDisable}>
              <label htmlFor="mfa-disable-code">
                Escribe un código válido para confirmar
              </label>
              <input
                id="mfa-disable-code"
                className="mfa-code-input"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={9}
                placeholder="123456"
                value={code}
                onChange={(event) => setCode(event.target.value)}
                required
              />
              <div className="form-actions">
                <button
                  className="primary-button delete-confirm-button"
                  type="submit"
                  disabled={busy || disableInvalid}
                >
                  {busy ? "Desactivando..." : "Desactivar definitivamente"}
                </button>
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => {
                    setShowDisable(false);
                    setCode("");
                    setError("");
                  }}
                  disabled={busy}
                >
                  Cancelar
                </button>
              </div>
            </form>
          ) : (
            <button
              className="secondary-button delete-account-trigger"
              type="button"
              onClick={() => {
                setShowDisable(true);
                setCode("");
                setError("");
                setNotice("");
              }}
            >
              Desactivar
            </button>
          )}
        </>
      )}

      {notice && (
        <p className="feedback success" role="status">
          {notice}
        </p>
      )}
      {error && (
        <p className="feedback error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
