import { FormEvent, StrictMode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  changeMasterPassword,
  deleteAccountFromPassword,
  loginWithMasterPassword,
  logoutFromMemory,
  registerWithMasterPassword,
} from "./auth";
import {
  Credential,
  createCredential,
  listCredentials,
  removeCredential,
  updateCredential,
} from "./vault";
import "./styles.css";
import { FIELD_LIMITS } from "./validation";
import {
  DEFAULT_PASSWORD_CHARACTER_SELECTION,
  generateSecurePassword,
  PASSWORD_GENERATOR_DEFAULT_LENGTH,
  PASSWORD_GENERATOR_MAX_LENGTH,
  PASSWORD_GENERATOR_MIN_LENGTH,
  PasswordCharacterOption,
} from "./password-generator";
import { getTotpSnapshot } from "./totp";
import { auditVault } from "./vault-health";
import type { VaultHealthAlert } from "./vault-health";
import { checkCredentialsBreach } from "./hibp";
import { SecurityDashboard } from "./SecurityDashboard";
import { CredentialDetail } from "./CredentialDetail";

type View = "login" | "register";
type Toast = { id: number; message: string; type: "success" | "error"; exiting?: boolean };
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

type Theme = "dark" | "light";

const THEME_KEY = "arca_theme";

function getInitialTheme(): Theme {
  const stored = localStorage.getItem(THEME_KEY);
  if (stored === "light" || stored === "dark") return stored;
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function applyTheme(theme: Theme) {
  document.documentElement.setAttribute("data-theme", theme);
}

function ThemeSwitcher() {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);

  useEffect(() => {
    applyTheme(theme);
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    function onChange(e: MediaQueryListEvent) {
      if (!localStorage.getItem(THEME_KEY)) {
        setTheme(e.matches ? "light" : "dark");
      }
    }
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const toggle = useCallback(() => {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  }, []);

  return (
    <button
      className="theme-toggle"
      type="button"
      onClick={toggle}
      aria-label={theme === "dark" ? "Cambiar a tema claro" : "Cambiar a tema oscuro"}
    >
      {theme === "dark" ? "☀" : "☾"}
    </button>
  );
}
// Estado inicial reutilizado al abrir el formulario y al limpiar una credencial.
const emptyCredential: Credential = {
  title: "",
  username: "",
  password: "",
  urls: [""],
};

function TotpCode({ secret, onCopy }: { secret: string; onCopy?: () => void }) {
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
      onCopy?.();
    } catch {
      setError("No se pudo copiar el código");
    }
  }

  if (error) return <p className="totp-error" role="status">{error}</p>;
  if (!snapshot) return <p className="totp-loading" role="status">Calculando código...</p>;

  const isCritical = snapshot.remainingSeconds <= 5;

  return (
    <div className={`totp-panel${isCritical ? " totp-critical" : ""}`} aria-label="Código de autenticación de dos factores">
      <div className="totp-panel-heading">
        <span>Código 2FA</span>
        <span>{snapshot.remainingSeconds}s</span>
      </div>
      <div className="totp-code-row">
        <output className="totp-code" aria-live="polite" aria-label="Código TOTP">
          {snapshot.code}
        </output>
        <button className="totp-copy-button" type="button" onClick={copyCode}>
          {copied ? "Copiado" : "Copiar"}
        </button>
      </div>
      <div className={`totp-progress${isCritical ? " totp-progress-critical" : ""}`} role="progressbar" aria-label="Tiempo restante del código" aria-valuemin={0} aria-valuemax={30} aria-valuenow={snapshot.remainingSeconds}>
        <span style={{ transform: `scaleX(${snapshot.progress})` }} />
      </div>
    </div>
  );
}

const passwordCharacterLabels: Record<PasswordCharacterOption, string> = {
  uppercase: "Mayúsculas",
  lowercase: "Minúsculas",
  numbers: "Números",
  symbols: "Símbolos",
};

function PasswordGenerator({
  onGenerate,
}: {
  onGenerate: (password: string) => void;
}) {
  const [length, setLength] = useState(PASSWORD_GENERATOR_DEFAULT_LENGTH);
  const [selection, setSelection] = useState(DEFAULT_PASSWORD_CHARACTER_SELECTION);
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [showGeneratedPassword, setShowGeneratedPassword] = useState(false);

  function toggleCharacterSet(option: PasswordCharacterOption) {
    setSelection((current) => ({ ...current, [option]: !current[option] }));
  }

  function generatePassword() {
    const password = generateSecurePassword(length, selection);
    onGenerate(password);
    setGeneratedPassword(password);
    setShowGeneratedPassword(false);
  }

  return (
    <div className="password-generator" aria-label="Generador de contraseña segura">
      <div className="generator-heading">
        <span>Generador seguro</span>
        <span>{length} caracteres</span>
      </div>
      {generatedPassword && (
        <div className="generated-preview">
          <input
            type={showGeneratedPassword ? "text" : "password"}
            value={generatedPassword}
            readOnly
            aria-label="Contraseña generada"
          />
          <button
            className="preview-button"
            type="button"
            onClick={() => setShowGeneratedPassword((visible) => !visible)}
            aria-label={showGeneratedPassword ? "Ocultar contraseña generada" : "Mostrar contraseña generada"}
          >
            {showGeneratedPassword ? "Ocultar" : "Mostrar"}
          </button>
        </div>
      )}
      <label className="length-control" htmlFor="password-length">
        <span>Longitud</span>
        <input
          id="password-length"
          type="range"
          min={PASSWORD_GENERATOR_MIN_LENGTH}
          max={PASSWORD_GENERATOR_MAX_LENGTH}
          value={length}
          onChange={(event) => setLength(Number(event.target.value))}
        />
      </label>
      <div className="character-options" aria-label="Tipos de caracteres">
        {(Object.keys(passwordCharacterLabels) as PasswordCharacterOption[]).map((option) => (
          <label key={option}>
            <input
              type="checkbox"
              checked={selection[option]}
              onChange={() => toggleCharacterSet(option)}
            />
            <span>{passwordCharacterLabels[option]}</span>
          </label>
        ))}
      </div>
      <button
        className="secondary-button generator-button"
        type="button"
        onClick={generatePassword}
        disabled={Object.values(selection).every((selected) => !selected)}
      >
        Generar contraseña
      </button>
    </div>
  );
}

function AccountModal({
  open,
  onClose,
  busy,
  onSubmitPassword,
  deletePassword,
  onDeletePasswordChange,
  onDeleteConfirm,
  isDeleting,
  deleteError,
}: {
  open: boolean;
  onClose: () => void;
  busy: boolean;
  onSubmitPassword: (event: FormEvent<HTMLFormElement>) => void;
  deletePassword: string;
  onDeletePasswordChange: (value: string) => void;
  onDeleteConfirm: () => void;
  isDeleting: boolean;
  deleteError: string | null;
}) {
  const modalRef = useRef<HTMLDialogElement>(null);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    const modal = modalRef.current;
    if (!modal) return;
    if (open && !modal.open) modal.showModal();
    if (!open && modal.open) {
      modal.close();
      formRef.current?.reset();
    }
  }, [open]);

  return (
    <dialog className="credential-modal account-modal" ref={modalRef} onCancel={onClose}>
      <div className="section-heading">
        <div>
          <p className="eyebrow">Ajustes de seguridad</p>
          <h2 id="account-modal-title">Mi Cuenta</h2>
        </div>
        <button className="modal-close-button" type="button" onClick={onClose} aria-label="Cerrar modal">
          ×
        </button>
      </div>

      <div className="account-section">
        <h3 className="account-section-title">Cambiar contraseña maestra</h3>
        <form className="credential-form" ref={formRef} onSubmit={onSubmitPassword}>
          <label htmlFor="current-master-password">Contraseña actual</label>
          <input
            id="current-master-password"
            name="currentPassword"
            type="password"
            autoComplete="current-password"
            minLength={12}
            maxLength={FIELD_LIMITS.masterPassword}
            required
          />
          <label htmlFor="new-master-password">Nueva contraseña</label>
          <input
            id="new-master-password"
            name="newPassword"
            type="password"
            autoComplete="new-password"
            minLength={12}
            maxLength={FIELD_LIMITS.masterPassword}
            required
          />
          <label htmlFor="confirm-master-password">
            Confirmar nueva contraseña
          </label>
          <input
            id="confirm-master-password"
            name="confirmPassword"
            type="password"
            autoComplete="new-password"
            minLength={12}
            maxLength={FIELD_LIMITS.masterPassword}
            required
          />
          <button className="primary-button" type="submit" disabled={busy}>
            {busy ? "Actualizando..." : "Cambiar contraseña"}
          </button>
        </form>
      </div>

      <div className="account-section danger-zone">
        <h3 className="danger-zone-title">Zona de Peligro</h3>
        <p className="danger-zone-description">
          Eliminar tu cuenta borrará permanentemente todos tus datos cifrados.
          Esta acción no se puede deshacer.
        </p>
        {deletePassword !== "" ? (
          <div className="delete-confirm-field">
            <label htmlFor="delete-confirm-password">
              Escribe tu contraseña actual para confirmar
            </label>
            <input
              id="delete-confirm-password"
              type="password"
              autoComplete="current-password"
              placeholder="Contraseña actual"
              value={deletePassword}
              onChange={(e) => onDeletePasswordChange(e.target.value)}
              minLength={12}
              maxLength={FIELD_LIMITS.masterPassword}
            />
            {deleteError && <p className="breach-error">{deleteError}</p>}
            <div className="confirm-actions">
              <button
                className="primary-button delete-confirm-button"
                type="button"
                onClick={onDeleteConfirm}
                disabled={isDeleting || deletePassword.length < 12}
              >
                {isDeleting ? "Eliminando..." : "Eliminar cuenta permanentemente"}
              </button>
              <button
                className="secondary-button"
                type="button"
                onClick={() => onDeletePasswordChange("")}
              >
                Cancelar
              </button>
            </div>
          </div>
        ) : (
          <button
            className="secondary-button delete-account-trigger"
            type="button"
            onClick={() => onDeletePasswordChange(" ")}
          >
            Eliminar Cuenta
          </button>
        )}
      </div>
    </dialog>
  );
}

/** Presenta los formularios de registro/login y los mensajes de resultado de la operación. */
function AuthPanel({
  view,
  setView,
  email,
  setEmail,
  masterPassword,
  setMasterPassword,
  busy,
  message,
  error,
  onSubmit,
}: {
  view: View;
  setView: (view: View) => void;
  email: string;
  setEmail: (value: string) => void;
  masterPassword: string;
  setMasterPassword: (value: string) => void;
  busy: boolean;
  message: string;
  error: string;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <section className="auth-card" aria-labelledby="auth-title">
      <div className="auth-card-top">
        <span className="live-indicator" aria-hidden="true" />{" "}
        <span>Acceso privado</span>
      </div>
      <p className="kicker">
        {view === "login" ? "Vuelve a tus accesos" : "Tu espacio empieza aquí"}
      </p>
      <h2 id="auth-title">
        {view === "login" ? "Abre tu bóveda" : "Crea tu bóveda"}
      </h2>
      <div className="auth-tabs" role="tablist" aria-label="Tipo de acceso">
        <button
          className={view === "login" ? "auth-tab active" : "auth-tab"}
          type="button"
          role="tab"
          aria-selected={view === "login"}
          onClick={() => setView("login")}
        >
          Iniciar sesión
        </button>
        <button
          className={view === "register" ? "auth-tab active" : "auth-tab"}
          type="button"
          role="tab"
          aria-selected={view === "register"}
          onClick={() => setView("register")}
        >
          Crear cuenta
        </button>
      </div>
      <form className="auth-form" onSubmit={onSubmit}>
        <label htmlFor="email">Correo electrónico</label>
        <input
          id="email"
          type="email"
          maxLength={FIELD_LIMITS.email}
          autoComplete="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          required
        />
        <label htmlFor="master-password">Contraseña maestra</label>
        <input
          id="master-password"
          type="password"
          maxLength={FIELD_LIMITS.masterPassword}
          minLength={12}
          autoComplete={view === "login" ? "current-password" : "new-password"}
          value={masterPassword}
          onChange={(event) => setMasterPassword(event.target.value)}
          required
        />
        <button className="primary-button" type="submit" disabled={busy}>
          {busy
            ? "Procesando..."
            : view === "login"
              ? "Desbloquear bóveda"
              : "Crear bóveda"}
        </button>
      </form>
      <p className="auth-note">
        <span aria-hidden="true">✦</span> La contraseña maestra nunca sale de tu
        dispositivo.
      </p>
      {message && (
        <p className="feedback success" role="status">
          {message}
        </p>
      )}
      {error && (
        <p className="feedback error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

function CryptoDemo() {
  const [input, setInput] = useState("");
  const [cipher, setCipher] = useState<{ iv: string; ciphertext: string } | null>(null);
  const [encrypting, setEncrypting] = useState(false);

  const encrypt = useCallback(async (plain: string) => {
    if (!plain) { setCipher(null); return; }
    setEncrypting(true);
    try {
      const enc = new TextEncoder();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"]);
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plain));
      setCipher({
        iv: Array.from(iv).map((b) => b.toString(16).padStart(2, "0")).join(""),
        ciphertext: Array.from(new Uint8Array(ct)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 96) + "…",
      });
    } catch { setCipher(null); }
    finally { setEncrypting(false); }
  }, []);

  useEffect(() => {
    const t = setTimeout(() => encrypt(input), 300);
    return () => clearTimeout(t);
  }, [input, encrypt]);

  return (
    <div className="crypto-demo">
      <div className="demo-header">
        <span className="demo-dot" />
        <span className="demo-dot demo-dot--warn" />
        <span className="demo-dot demo-dot--safe" />
        <span className="demo-title">crypto-demo.local</span>
      </div>
      <div className="demo-body">
        <label className="demo-label" htmlFor="demo-input">Texto plano</label>
        <input
          id="demo-input"
          className="demo-input"
          type="text"
          placeholder="Escribe algo para cifrar…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <div className="demo-output-grid">
          <div className="demo-output-block">
            <span className="demo-tag">CIPHERTEXT</span>
            <code className="demo-code">
              {cipher ? cipher.ciphertext : "af09c1b3e7…"}
            </code>
          </div>
          <div className="demo-output-block">
            <span className="demo-tag">IV (12 bytes)</span>
            <code className="demo-code demo-code--iv">
              {cipher ? cipher.iv : "a4f208e19c3b…"}
            </code>
          </div>
        </div>
        <p className="demo-footnote">
          {encrypting
            ? "Cifrando con AES-256-GCM…"
            : cipher
              ? "Generado localmente con Web Crypto API. El servidor jamás ve este dato."
              : "Escribe para ver cómo se cifra en tu navegador."}
        </p>
      </div>
    </div>
  );
}

/** Página pública que explica el modelo zero-knowledge y dirige al formulario de acceso. */
function Landing({ onAccess }: { onAccess: () => void }) {
  const [visibleSections, setVisibleSections] = useState<Set<string>>(new Set());

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setVisibleSections((prev) => new Set(prev).add(entry.target.getAttribute("data-reveal") || ""));
          }
        });
      },
      { threshold: 0.15, rootMargin: "0px 0px -40px 0px" },
    );
    document.querySelectorAll("[data-reveal]").forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  const reveal = (id: string) => visibleSections.has(id) ? "revealed" : "";

  return (
    <div className="landing-page">
      <div className="landing-grid-bg" aria-hidden="true" />
      <header className="site-header">
        <a className="brand" href="/" aria-label="Arca, inicio">
          <span className="brand-symbol">A</span>
          <span>arca</span>
        </a>
        <nav className="site-nav" aria-label="Navegación principal">
          <a href="#arquitectura">Arquitectura</a>
          <a href="#funcionalidades">Funcionalidades</a>
          <button type="button" onClick={onAccess}>
            Entrar
          </button>
          <ThemeSwitcher />
        </nav>
      </header>
      <main>
        {/* ── Hero ── */}
        <section className="hero-section" aria-labelledby="hero-title">
          <div className="hero-copy">
            <div className="hero-badges">
              <span className="security-badge">Zero-Knowledge</span>
            </div>
            <h1 id="hero-title">
              Tus secretos nunca salen de
              <br />
              <span>tu dispositivo.</span>
            </h1>
            <p className="hero-description">
              Arca deriva tus claves de cifrado directamente en tu navegador con
              y cifra cada credencial antes de tocar la red.
              El servidor solo almacena blobs indescifrables.
            </p>
            <div className="hero-actions">
              <button className="primary-button hero-cta" type="button" onClick={onAccess}>
                Probar Bóveda <span aria-hidden="true">↗</span>
              </button>
            </div>
          </div>
          <CryptoDemo />
        </section>

        {/* ── Signal bar ── */}
        <section className="signal-bar" aria-label="Principios de seguridad">
          <span><i className="signal-dot" /> Cifrado local</span>
          <span><i className="signal-dot" /> Tu clave nunca se almacena</span>
          <span><i className="signal-dot" /> Sesiones temporales</span>
          <span><i className="signal-dot" /> Auditoría en tiempo real</span>
        </section>

        {/* ── Architecture: Backend Ciego ── */}
        <section className="arch-section" id="arquitectura" aria-labelledby="arch-title" data-reveal="arch">
          <div className={`section-intro reveal-item ${reveal("arch")}`}>
            <p className="kicker">Backend Ciego — Zero-Knowledge</p>
            <h2 id="arch-title">Así se ve la privacidad por diseño.</h2>
            <p>Tus credenciales nunca están en texto plano en ningún servidor. Cada paso ocurre en tu RAM.</p>
          </div>
          <div className="arch-steps">
            <article className={`arch-card reveal-item ${reveal("arch")}`} style={{ animationDelay: "100ms" }}>
              <span className="arch-step-num">01</span>
              <div className="arch-icon">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/>
                  <circle cx="12" cy="12" r="4"/>
                </svg>
              </div>
              <h3>Derivación de clave</h3>
              <p>Arca genera tu clave en la RAM del navegador. Nunca sale de tu dispositivo.</p>
              <span className="arch-tag">600K iteraciones</span>
            </article>
            <article className={`arch-card reveal-item ${reveal("arch")}`} style={{ animationDelay: "250ms" }}>
              <span className="arch-step-num">02</span>
              <div className="arch-icon">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                  <circle cx="12" cy="16" r="1"/>
                </svg>
              </div>
              <h3>Cifrado AES-GCM</h3>
              <p>Cada payload se cifra antes de tocar la red. El navegador genera solo texto ilegibles.</p>
              <span className="arch-tag">AES-256-GCM</span>
            </article>
            <article className={`arch-card reveal-item ${reveal("arch")}`} style={{ animationDelay: "400ms" }}>
              <span className="arch-step-num">03</span>
              <div className="arch-icon">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
                </svg>
              </div>
              <h3>La base de datos no conoce tus credenciales</h3>
              <p>El servidor solo recibe datos cifrados. Arca no puede leer tus credenciales — solo tú tienes la clave.</p>
              <span className="arch-tag">Zero-Knowledge</span>
            </article>
          </div>
        </section>

        {/* ── Features showcase ── */}
        <section className="features-section" id="funcionalidades" aria-labelledby="features-title" data-reveal="features">
          <div className={`section-intro reveal-item ${reveal("features")}`}>
            <p className="kicker">Funcionalidades avanzadas</p>
            <h2 id="features-title">Seguridad sin complejidad.</h2>
          </div>
          <div className="features-grid">
            <article className={`feature-card reveal-item ${reveal("features")}`} style={{ animationDelay: "80ms" }}>
              <div className="feature-icon feature-icon--health">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                </svg>
              </div>
              <h3>Auditoría de Salud</h3>
              <p>Analiza entropía, detecta contraseñas débiles y reutilizadas en tiempo real. Scores y métricas para cada credencial.</p>
              <span className="feature-tag">Entropía · Scores · Métricas</span>
            </article>
            <article className={`feature-card reveal-item ${reveal("features")}`} style={{ animationDelay: "200ms" }}>
              <div className="feature-icon feature-icon--breach">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                  <line x1="12" y1="9" x2="12" y2="13"/>
                  <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
              </div>
              <h3>Alertas de Brechas HIBP</h3>
              <p>
                Verifica credenciales contra Have I Been Pwned usando k-Anonymity:
                solo el hash SHA-1 (5 prefijos) sale de tu dispositivo, nunca tu contraseña completa.
              </p>
              <span className="feature-tag">k-Anonymity · SHA-1 local</span>
            </article>
            <article className={`feature-card reveal-item ${reveal("features")}`} style={{ animationDelay: "320ms" }}>
              <div className="feature-icon feature-icon--totp">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
              </div>
              <h3>Autenticador TOTP 2FA</h3>
              <p>Genera códigos de autenticación de dos factores directamente desde tu bóveda. Cronómetro visual en tiempo real.</p>
              <span className="feature-tag">TOTP · Cronómetro en vivo</span>
            </article>
          </div>
        </section>

        {/* ── FAQ ── */}
        <section className="faq-section" aria-labelledby="faq-title" data-reveal="faq">
          <div className={`section-intro reveal-item ${reveal("faq")}`}>
            <p className="kicker">Preguntas honestas</p>
            <h2 id="faq-title">Lo que necesitas saber antes de empezar.</h2>
          </div>
          <div className="faq-list">
            <details>
              <summary>¿Puede Arca ver mis contraseñas?</summary>
              <p>No. Tus credenciales se cifran en el dispositivo y el servidor no recibe los valores legibles. El cifrado ocurre 100% en tu navegador con Web Crypto API.</p>
            </details>
            <details>
              <summary>¿Qué pasa si olvido mi contraseña maestra?</summary>
              <p>No existe una copia de recuperación. Es la consecuencia directa de que nadie más — ni siquiera nosotros — pueda abrir tu bóveda.</p>
            </details>
            <details>
              <summary>¿Cómo funciona la verificación de brechas?</summary>
              <p>Usamos k-Anonymity con HIBP: calculamos SHA-1 de tu contraseña localmente y solo enviamos los 5 primeros caracteres del hash. Tu contraseña completa nunca sale del navegador.</p>
            </details>
          </div>
        </section>

        {/* ── Closing CTA ── */}
        <section className="closing-section" data-reveal="closing">
          <div className={`closing-inner reveal-item ${reveal("closing")}`}>
            <h2>
              Menos exposición.
              <br />
              <span>Más control.</span>
            </h2>
            <p className="closing-description">
              Tus secretos son tuyos. Arca solo guarda lo que tú decides cifrar.
            </p>
            <button className="primary-button hero-cta" type="button" onClick={onAccess}>
              Abrir mi bóveda <span aria-hidden="true">↗</span>
            </button>
          </div>
        </section>
      </main>
      <footer className="site-footer">
        <span>arca / privacidad primero</span>
        <span>Construido para guardar lo importante</span>
      </footer>
    </div>
  );
}

function VaultSkeleton() {
  return (
    <div className="vault-skeleton" aria-hidden="true">
      <div className="skeleton-row">
        <div className="skeleton-block skeleton-progress" style={{ width: "100%", height: 8 }} />
      </div>
      <div className="skeleton-stats">
        <div className="skeleton-block skeleton-stat" />
        <div className="skeleton-block skeleton-stat" />
        <div className="skeleton-block skeleton-stat" />
      </div>
      {[0, 1, 2].map((i) => (
        <div className="skeleton-card" key={i}>
          <div className="skeleton-row">
            <div className="skeleton-block skeleton-avatar" />
            <div className="skeleton-lines">
              <div className="skeleton-block skeleton-line skeleton-line--medium" />
              <div className="skeleton-block skeleton-line skeleton-line--short" />
            </div>
            <div className="skeleton-actions">
              <div className="skeleton-block skeleton-action" />
              <div className="skeleton-block skeleton-action" />
              <div className="skeleton-block skeleton-action" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/** Coordina la navegación, la sesión en memoria y las operaciones CRUD de la bóveda. */
function App() {
  const [view, setView] = useState<View>("login");
  const [showAccess, setShowAccess] = useState(false);
  const [email, setEmail] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [authenticated, setAuthenticated] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [credentials, setCredentials] = useState<
    Array<Credential & { id: number | string }>
  >([]);
  const [credential, setCredential] = useState<Credential>(emptyCredential);
  const [editingId, setEditingId] = useState<number | string | null>(null);
  const [isCredentialModalOpen, setIsCredentialModalOpen] = useState(false);
  const [isAccountModalOpen, setIsAccountModalOpen] = useState(false);
  const credentialModalRef = useRef<HTMLDialogElement>(null);
  const deleteConfirmModalRef = useRef<HTMLDialogElement>(null);
  const [deletingId, setDeletingId] = useState<number | string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastIdRef = useRef(0);
  const [selectedCredentialId, setSelectedCredentialId] = useState<number | string | null>(null);
  const [breachedAlerts, setBreachedAlerts] = useState<VaultHealthAlert[]>([]);
  const [isCheckingBreach, setIsCheckingBreach] = useState(false);
  const [checkedCount, setCheckedCount] = useState(0);
  const [breachError, setBreachError] = useState<string | null>(null);
  const [deletePassword, setDeletePassword] = useState("");
  const [isDeletingAccount, setIsDeletingAccount] = useState(false);

  function addToast(msg: string, type: Toast["type"] = "success") {
    const id = ++toastIdRef.current;
    setToasts((prev) => [...prev, { id, message: msg, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.map((t) => t.id === id ? { ...t, exiting: true } : t));
    }, 2750);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3000);
  }

  const healthReport = useMemo(() => auditVault(credentials, breachedAlerts), [credentials, breachedAlerts]);
  const affectedIds = useMemo(() => {
    const ids = new Set<number | string>();
    for (const alert of healthReport.reused) ids.add(alert.id);
    for (const alert of healthReport.weak) ids.add(alert.id);
    for (const alert of healthReport.breached) ids.add(alert.id);
    return ids;
  }, [healthReport]);
  const breachedIds = useMemo(() => {
    const ids = new Set<number | string>();
    for (const alert of healthReport.breached) ids.add(alert.id);
    return ids;
  }, [healthReport]);

  async function handleCheckBreach() {
    setIsCheckingBreach(true);
    setCheckedCount(0);
    setBreachError(null);

    try {
      const alerts = await checkCredentialsBreach(credentials, (checked) => {
        setCheckedCount(checked);
      });
      setBreachedAlerts(alerts);
    } catch {
      setBreachError("No se pudo conectar con Have I Been Pwned. Inténtalo de nuevo.");
    } finally {
      setIsCheckingBreach(false);
    }
  }

  useEffect(() => {
    const modal = credentialModalRef.current;
    if (!modal) return;
    if (isCredentialModalOpen && !modal.open) modal.showModal();
    if (!isCredentialModalOpen && modal.open) modal.close();
  }, [isCredentialModalOpen]);

  useEffect(() => {
    const modal = deleteConfirmModalRef.current;
    if (!modal) return;
    if (deletingId !== null && !modal.open) modal.showModal();
    if (deletingId === null && modal.open) modal.close();
  }, [deletingId]);

  /** Registra una cuenta o inicia sesión y carga las credenciales tras desbloquear la bóveda. */
  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      if (view === "register") {
        await registerWithMasterPassword(email, masterPassword);
        setView("login");
        setMessage("Cuenta creada. Inicia sesión para abrir tu bóveda.");
      } else {
        await loginWithMasterPassword(email, masterPassword);
        setAuthenticated(true);
        setDecrypting(true);
        setCredentials(await listCredentials());
        setDecrypting(false);
        setMessage("Bóveda desbloqueada en memoria.");
      }
      setMasterPassword("");
    } catch (submitError) {
      setError(
        submitError instanceof Error
          ? submitError.message
          : "No se pudo completar la operación",
      );
    } finally {
      setBusy(false);
    }
  }
  /** Cierra la sesión remota y limpia todo el estado sensible de la interfaz. */
  async function handleLogout() {
    setBusy(true);
    setError("");
    try {
      await logoutFromMemory();
      setMessage("Sesión cerrada.");
    } catch (logoutError) {
      setError(
        logoutError instanceof Error
          ? logoutError.message
          : "No se pudo cerrar la sesión",
      );
    } finally {
      setAuthenticated(false);
      setDecrypting(false);
      setCredentials([]);
      setCredential(emptyCredential);
      setEditingId(null);
      setIsCredentialModalOpen(false);
      setIsAccountModalOpen(false);
      setDeletingId(null);
      setBreachedAlerts([]);
      setIsCheckingBreach(false);
      setCheckedCount(0);
      setBreachError(null);
      setSelectedCredentialId(null);
      setBusy(false);
    }
  }
  /** Cambia la contraseña localmente y obliga a iniciar una sesión nueva. */
  async function handleChangePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    const form = new FormData(event.currentTarget);
    const currentPassword = String(form.get("currentPassword") || "");
    const newPassword = String(form.get("newPassword") || "");
    const confirmPassword = String(form.get("confirmPassword") || "");
    try {
      if (newPassword !== confirmPassword)
        throw new Error("Las nuevas contraseñas no coinciden");
      await changeMasterPassword(currentPassword, newPassword);
      setAuthenticated(false);
      setDecrypting(false);
      setCredentials([]);
      setCredential(emptyCredential);
      setEditingId(null);
      setIsAccountModalOpen(false);
      setView("login");
      setShowAccess(true);
      setMessage("Contraseña actualizada. Inicia sesión de nuevo.");
    } catch (changeError) {
      setError(
        changeError instanceof Error
          ? changeError.message
          : "No se pudo cambiar la contraseña",
      );
    } finally {
      setBusy(false);
    }
  }
  async function handleDeleteAccount() {
    setIsDeletingAccount(true);
    setError("");
    try {
      await deleteAccountFromPassword(deletePassword);
      localStorage.clear();
      setAuthenticated(false);
      setDecrypting(false);
      setCredentials([]);
      setCredential(emptyCredential);
      setEditingId(null);
      setIsAccountModalOpen(false);
      setSelectedCredentialId(null);
      setDeletePassword("");
      setView("login");
      setShowAccess(true);
      addToast("Cuenta eliminada permanentemente.", "success");
    } catch (deleteError) {
      setError(
        deleteError instanceof Error
          ? deleteError.message
          : "No se pudo eliminar la cuenta",
      );
    } finally {
      setIsDeletingAccount(false);
    }
  }
  function updateCredentialUrl(index: number, value: string) {
    setCredential((current) => ({
      ...current,
      urls: current.urls.map((url, currentIndex) =>
        currentIndex === index ? value : url,
      ),
    }));
  }
  function addCredentialUrl() {
    if (credential.urls.length < FIELD_LIMITS.maxUrls) {
      setCredential((current) => ({ ...current, urls: [...current.urls, ""] }));
    }
  }
  function removeCredentialUrl(index: number) {
    if (credential.urls.length > 1) {
      setCredential((current) => ({
        ...current,
        urls: current.urls.filter((_, currentIndex) => currentIndex !== index),
      }));
    }
  }
  /** Crea o actualiza una credencial; el módulo vault cifra antes de llamar a la API. */
  async function handleCredentialSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (editingId === null) {
        const created = await createCredential(credential);
        setCredentials((current) => [...current, created]);
        setMessage("Credencial cifrada y guardada.");
      } else {
        const updated = await updateCredential(editingId, credential);
        setCredentials((current) =>
          current.map((item) => (item.id === editingId ? updated : item)),
        );
        setMessage("Credencial actualizada.");
      }
      setCredential(emptyCredential);
      setEditingId(null);
      setIsCredentialModalOpen(false);
    } catch (saveError) {
      setError(
        saveError instanceof Error
          ? saveError.message
          : "No se pudo guardar la credencial",
      );
    } finally {
      setBusy(false);
    }
  }
  function closeCredentialModal() {
    setIsCredentialModalOpen(false);
    setEditingId(null);
    setCredential(emptyCredential);
    setError("");
  }
  function closeAccountModal() {
    setIsAccountModalOpen(false);
    setError("");
    setDeletePassword("");
  }
  function openAccountModal() {
    setError("");
    setDeletePassword("");
    setIsAccountModalOpen(true);
  }
  function openNewCredentialModal() {
    setEditingId(null);
    setCredential(emptyCredential);
    setError("");
    setIsCredentialModalOpen(true);
  }
  function openEditCredentialModal(id: number | string) {
    const selectedCredential = credentials.find((item) => item.id === id);
    if (!selectedCredential) return;
    setEditingId(id);
    setCredential(selectedCredential);
    setError("");
    setIsCredentialModalOpen(true);
  }
  /** Elimina una credencial en el servidor y sincroniza la lista local. */
  async function handleDelete(id: number | string) {
    setBusy(true);
    setError("");
    setDeletingId(null);
    try {
      await removeCredential(id);
      setCredentials((current) => current.filter((item) => item.id !== id));
      if (editingId === id) {
        setCredential(emptyCredential);
        setEditingId(null);
      }
      setMessage("Credencial eliminada.");
    } catch (deleteError) {
      setError(
        deleteError instanceof Error
          ? deleteError.message
          : "No se pudo eliminar la credencial",
      );
    } finally {
      setBusy(false);
    }
  }

  if (!authenticated && !showAccess)
    return (
      <Landing
        onAccess={() => {
          setShowAccess(true);
          setView("register");
        }}
      />
    );
  if (!authenticated)
    return (
      <main className="auth-page">
        <header className="site-header">
          <a className="brand" href="/" aria-label="Arca, inicio">
            <span className="brand-symbol">A</span>
            <span>arca</span>
          </a>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <button
              className="back-link"
              type="button"
              onClick={() => setShowAccess(false)}
            >
              Volver al inicio
            </button>
            <ThemeSwitcher />
          </div>
        </header>
        <AuthPanel
          view={view}
          setView={(nextView) => {
            setView(nextView);
            setError("");
            setMessage("");
          }}
          email={email}
          setEmail={setEmail}
          masterPassword={masterPassword}
          setMasterPassword={setMasterPassword}
          busy={busy}
          message={message}
          error={error}
          onSubmit={handleSubmit}
        />
      </main>
    );

  return (
    <main className="app-shell vault-shell">
      <header className="workspace-header">
        <a className="brand" href="/" aria-label="Arca, inicio">
          <span className="brand-symbol">A</span>
          <span>arca</span>
        </a>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <button
            className="text-button"
            type="button"
            onClick={handleLogout}
            disabled={busy}
          >
            {busy ? "Cerrando..." : "Cerrar sesión"}
          </button>
          <ThemeSwitcher />
        </div>
      </header>
      {decrypting ? (
        <VaultSkeleton />
      ) : (<>
      <SecurityDashboard
        credentials={credentials}
        healthReport={healthReport}
        breachedCount={breachedIds.size}
        isChecking={isCheckingBreach}
        checkedCount={checkedCount}
        breachError={breachError}
        onCheckBreach={handleCheckBreach}
      />
      <div className="vault-split-container">
        <section className="credential-list-panel" aria-label="Lista de credenciales">
          <div className="credential-list-header">
            <div className="credential-search-wrapper">
              <svg className="credential-search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <input
                className="credential-search-input"
                type="text"
                placeholder="Buscar credenciales..."
                aria-label="Buscar credenciales"
              />
            </div>
            <button className="credential-add-button" type="button" onClick={openNewCredentialModal}>
              + Nueva
            </button>
          </div>
          <div className="credential-items-list">
            {credentials.length === 0 && (
              <div className="credential-list-empty">
                <div className="credential-list-empty-icon">+</div>
                <p>Añade tu primer acceso para tenerlo disponible cuando lo necesites.</p>
              </div>
            )}
            {credentials.map((item) => {
              const firstUrl = item.urls.find((u) => u.length > 0);
              const faviconUrl = firstUrl ? getFaviconUrl(firstUrl) : null;
              const isAffected = affectedIds.has(item.id);
              const isBreached = breachedIds.has(item.id);
              const hasTotp = Boolean(item.totpSecret);
              const isSelected = selectedCredentialId === item.id;

              return (
                <button
                  className={`credential-item ${isSelected ? "credential-item--active" : ""} ${isAffected ? "credential-item--affected" : ""}`}
                  type="button"
                  key={item.id}
                  onClick={() => setSelectedCredentialId(item.id)}
                >
                  <div className="credential-item-avatar">
                    {faviconUrl ? (
                      <img
                        className="credential-item-favicon"
                        src={faviconUrl}
                        alt=""
                        width="24"
                        height="24"
                        onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = "none"; }}
                      />
                    ) : null}
                    <span className={`credential-item-avatar-fallback ${faviconUrl ? "credential-item-avatar-fallback--hidden" : ""}`}>
                      {item.title.charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <div className="credential-item-content">
                    <span className="credential-item-title">{item.title}</span>
                    <span className="credential-item-username">{item.username}</span>
                  </div>
                  <div className="credential-item-badges">
                    {hasTotp && <span className="credential-item-badge credential-item-badge--2fa">2FA</span>}
                    {isBreached && <span className="credential-item-badge credential-item-badge--breach">!</span>}
                    {!isBreached && isAffected && <span className="credential-item-badge credential-item-badge--weak">!</span>}
                  </div>
                </button>
              );
            })}
          </div>
          <div className="sidebar-footer">
            <button className="sidebar-account-button" type="button" onClick={openAccountModal}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                <circle cx="12" cy="7" r="4"/>
              </svg>
              Mi Cuenta
            </button>
          </div>
        </section>
        <section className="credential-detail-panel" aria-label="Detalle de credencial">
          <CredentialDetail
            credential={credentials.find(c => c.id === selectedCredentialId) ?? null}
            onEdit={openEditCredentialModal}
            onDelete={(id) => setDeletingId(id)}
            breachedIds={breachedIds}
            busy={busy}
          />
        </section>
      </div>
      <AccountModal
        open={isAccountModalOpen}
        onClose={closeAccountModal}
        busy={busy}
        onSubmitPassword={handleChangePassword}
        deletePassword={deletePassword}
        onDeletePasswordChange={setDeletePassword}
        onDeleteConfirm={handleDeleteAccount}
        isDeleting={isDeletingAccount}
        deleteError={error}
      />
        <dialog className="credential-modal" ref={credentialModalRef} onCancel={closeCredentialModal}>
          <div className="section-heading">
            <h2 id="composer-title">
              {editingId === null ? "Guardar un acceso" : "Actualizar acceso"}
            </h2>
            <button className="modal-close-button" type="button" onClick={closeCredentialModal} aria-label="Cerrar modal">
              ×
            </button>
          </div>
          <form className="credential-form" onSubmit={handleCredentialSubmit}>
            <label htmlFor="credential-title">Nombre</label>
            <input
              id="credential-title"
              maxLength={FIELD_LIMITS.title}
              placeholder="Ej. GitHub"
              value={credential.title}
              onChange={(event) =>
                setCredential({ ...credential, title: event.target.value })
              }
              required
            />
            <label htmlFor="credential-username">Usuario</label>
            <input
              id="credential-username"
              maxLength={FIELD_LIMITS.username}
              autoComplete="off"
              placeholder="Tu nombre de usuario"
              value={credential.username}
              onChange={(event) =>
                setCredential({ ...credential, username: event.target.value })
              }
              required
            />
            <label htmlFor="credential-password">Contraseña</label>
            <input
              id="credential-password"
              maxLength={FIELD_LIMITS.password}
              type="password"
              autoComplete="new-password"
              placeholder="Contraseña del acceso"
              value={credential.password}
              onChange={(event) =>
                setCredential({ ...credential, password: event.target.value })
              }
              required
            />
            <PasswordGenerator
              onGenerate={(password) => setCredential({ ...credential, password })}
            />
            <label htmlFor="credential-totp-secret">
              Secreto TOTP / 2FA <span>Opcional</span>
            </label>
            <input
              id="credential-totp-secret"
              maxLength={FIELD_LIMITS.totpSecret}
              autoComplete="off"
              placeholder="Base32 o URI otpauth://"
              value={credential.totpSecret ?? ""}
              onChange={(event) =>
                setCredential({ ...credential, totpSecret: event.target.value })
              }
            />
            <fieldset className="url-fields">
              <legend>URLs <span>Opcional</span></legend>
              {credential.urls.map((url, index) => (
                <div className="url-row" key={`credential-url-${index}`}>
                  <input
                    id={`credential-url-${index}`}
                    maxLength={FIELD_LIMITS.url}
                    type="url"
                    autoComplete="off"
                    placeholder="https://"
                    value={url}
                    onChange={(event) => updateCredentialUrl(index, event.target.value)}
                  />
                  <button className="secondary-button" type="button" onClick={() => removeCredentialUrl(index)} disabled={credential.urls.length === 1}>
                    Quitar
                  </button>
                </div>
              ))}
              {credential.urls.length < FIELD_LIMITS.maxUrls && (
                <button className="secondary-button add-url-button" type="button" onClick={addCredentialUrl}>
                  Añadir URL
                </button>
              )}
            </fieldset>
            <div className="form-actions">
              <button className="primary-button" type="submit" disabled={busy}>
                {editingId === null ? "Guardar acceso" : "Guardar cambios"}
              </button>
              <button className="secondary-button" type="button" onClick={closeCredentialModal}>
                Cancelar
              </button>
            </div>
          </form>
        </dialog>
      {message && (
        <p className="feedback success" role="status">
          {message}
        </p>
      )}
      {error && (
        <p className="feedback error" role="alert">
          {error}
        </p>
      )}
      <dialog className="credential-modal confirm-modal" ref={deleteConfirmModalRef} onCancel={() => setDeletingId(null)}>
        <div className="confirm-modal-body">
          <div className="confirm-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          </div>
          <h2>Eliminar credencial</h2>
          <p>
            Se eliminará <strong>{deletingId !== null ? (credentials.find((c) => c.id === deletingId)?.title ?? "esta credencial") : ""}</strong> de tu bóveda. Esta acción no se puede deshacer.
          </p>
          <div className="confirm-actions">
            <button
              className="primary-button confirm-danger"
              type="button"
              onClick={() => handleDelete(deletingId!)}
              disabled={busy}
            >
              {busy ? "Eliminando..." : "Eliminar"}
            </button>
            <button
              className="secondary-button"
              type="button"
              onClick={() => setDeletingId(null)}
            >
              Cancelar
            </button>
          </div>
        </div>
      </dialog>
      </>)}
      <div className="toast-container" aria-live="polite">
        {toasts.map((t) => (
          <div className={`toast toast--${t.type}${t.exiting ? " toast--exit" : ""}`} key={t.id}>
            <svg className="toast-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
            <span className="toast-message">{t.message}</span>
            <div className="toast-progress"><span /></div>
          </div>
        ))}
      </div>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
