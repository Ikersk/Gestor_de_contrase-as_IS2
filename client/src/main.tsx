import { FormEvent, StrictMode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  changeMasterPassword,
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
import { VaultHealthPanel } from "./VaultHealthPanel";

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

function ChangePasswordPanel({
  open,
  onOpen,
  onClose,
  busy,
  onSubmit,
}: {
  open: boolean;
  onOpen: () => void;
  onClose: () => void;
  busy: boolean;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
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
    <section className="account-panel" aria-label="Configuración de la cuenta">
      <button className="secondary-button" type="button" onClick={onOpen}>
        Cambiar contraseña maestra
      </button>
      <dialog className="credential-modal account-modal" ref={modalRef} onCancel={onClose}>
        <div className="section-heading">
          <div>
            <p className="eyebrow">Seguridad de la cuenta</p>
            <h2 id="change-password-title">Cambiar contraseña maestra</h2>
          </div>
          <button className="modal-close-button" type="button" onClick={onClose} aria-label="Cerrar modal">
            ×
          </button>
        </div>
      <form className="credential-form" ref={formRef} onSubmit={onSubmit}>
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
        <button className="secondary-button modal-cancel-button" type="button" onClick={onClose}>
          Cancelar
        </button>
      </dialog>
    </section>
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

/** Página pública que explica el modelo zero-knowledge y dirige al formulario de acceso. */
function Landing({ onAccess }: { onAccess: () => void }) {
  return (
    <div className="landing-page">
      <header className="site-header">
        <a className="brand" href="/" aria-label="Arca, inicio">
          <span className="brand-symbol">A</span>
          <span>arca</span>
        </a>
        <nav className="site-nav" aria-label="Navegación principal">
          <a href="#principios">Principios</a>
          <button type="button" onClick={onAccess}>
            Entrar
          </button>
          <ThemeSwitcher />
        </nav>
      </header>
      <main>
        <section className="hero-section" aria-labelledby="hero-title">
          <div className="hero-copy">
            <p className="kicker">Gestor de accesos zero knowledge</p>
            <h1 id="hero-title">
              Tus accesos,
              <br />
              <span>bajo tus reglas.</span>
            </h1>
            <p className="hero-description">
              Arca cifra tus credenciales en tu dispositivo para que puedas
              guardar lo importante sin entregar tus secretos a nadie.
            </p>
            <div className="hero-actions">
              <button
                className="primary-button"
                type="button"
                onClick={onAccess}
              >
                Crear mi bóveda <span aria-hidden="true">↗</span>
              </button>
              <span className="risk-note">
                Gratis para empezar <span aria-hidden="true">·</span> Sin
                tarjeta
              </span>
            </div>
          </div>
          <div className="vault-art" aria-label="Diagrama de cifrado local">
            <div className="vault-art-grid" aria-hidden="true" />
            <div className="vault-core">
              <span className="core-mark">A</span>
              <span className="core-label">BÓVEDA</span>
            </div>
            <span className="orbit-label label-top">TU CLAVE MAESTRA</span>
            <span className="orbit-label label-right">ENCRIPTACIÓN</span>
            <span className="orbit-label label-bottom">SOLO TÚ</span>
            <span className="orbit-label secondary-label secondary-top">
              SEGURIDAD
            </span>
            <span className="orbit-label secondary-label secondary-right">
              SECRETOS
            </span>
            <span className="orbit-label secondary-label secondary-bottom">
              CIFRADO
            </span>
            <div className="orbit-line orbit-line-one" aria-hidden="true" />
            <div className="orbit-line orbit-line-two" aria-hidden="true" />
          </div>
        </section>
        <section className="signal-bar" aria-label="Principios de seguridad">
          <span>
            <i className="signal-dot" /> Cifrado local
          </span>
          <span>Tu clave nunca se almacena</span>
          <span>Sesiones temporales</span>
        </section>
        <section
          className="principles-section"
          id="principios"
          aria-labelledby="principles-title"
        >
          <div className="section-intro">
            <p className="kicker">La diferencia está en dónde ocurre</p>
            <h2 id="principles-title">Privacidad que se puede explicar.</h2>
            <p>
              No necesitas confiar a ciegas. Arca está diseñada para que el
              recorrido de tus credenciales sea fácil de entender.
            </p>
          </div>
          <div className="principles-grid">
            <article>
              <span className="principle-index">01</span>
              <h3>Se cifra antes de salir</h3>
              <p>
                Tu contraseña maestra deriva las claves en el navegador. El
                servidor recibe únicamente material cifrado.
              </p>
            </article>
            <article>
              <span className="principle-index">02</span>
              <h3>Se descifra cuando hace falta</h3>
              <p>
                La bóveda solo se abre en una sesión activa y la clave
                desaparece al cerrarla.
              </p>
            </article>
            <article>
              <span className="principle-index">03</span>
              <h3>Se organiza sin ruido</h3>
              <p>
                Guarda nombres, usuarios, contraseñas y URLs en una vista
                pensada para volver cada día.
              </p>
            </article>
          </div>
        </section>
        <section className="faq-section" aria-labelledby="faq-title">
          <div className="section-intro">
            <p className="kicker">Preguntas honestas</p>
            <h2 id="faq-title">Lo que necesitas saber antes de empezar.</h2>
          </div>
          <div className="faq-list">
            <details>
              <summary>¿Puede Arca ver mis contraseñas?</summary>
              <p>
                No. Tus credenciales se cifran en el dispositivo y el servidor
                no recibe los valores legibles.
              </p>
            </details>
            <details>
              <summary>¿Qué ocurre si olvido mi contraseña maestra?</summary>
              <p>
                No existe una copia de recuperación. Es la consecuencia de que
                nadie más pueda abrir tu bóveda.
              </p>
            </details>
            <details>
              <summary>¿Tiene coste crear una cuenta?</summary>
              <p>No. Puedes crear una cuenta y probar la bóveda sin tarjeta.</p>
            </details>
          </div>
        </section>
        <section className="closing-section">
          <div>
            <p className="kicker">Empieza con una decisión</p>
            <h2>
              Menos exposición.
              <br />
              Más control.
            </h2>
          </div>
          <button
            className="primary-button light-button"
            type="button"
            onClick={onAccess}
          >
            Abrir mi bóveda <span aria-hidden="true">↗</span>
          </button>
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
  const [isChangePasswordModalOpen, setIsChangePasswordModalOpen] = useState(false);
  const credentialModalRef = useRef<HTMLDialogElement>(null);
  const deleteConfirmModalRef = useRef<HTMLDialogElement>(null);
  const [revealedId, setRevealedId] = useState<number | string | null>(null);
  const [deletingId, setDeletingId] = useState<number | string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastIdRef = useRef(0);

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

  const healthReport = useMemo(() => auditVault(credentials), [credentials]);
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
      setIsChangePasswordModalOpen(false);
      setRevealedId(null);
      setDeletingId(null);
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
      setIsChangePasswordModalOpen(false);
      setRevealedId(null);
      setView("login");
      setShowAccess(true);
      setMessage("Contraseña actualizada. Inicia sesión de nuevo.");
      setIsChangePasswordModalOpen(false);
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
  function closeChangePasswordModal() {
    setIsChangePasswordModalOpen(false);
    setError("");
  }
  function openChangePasswordModal() {
    setError("");
    setIsChangePasswordModalOpen(true);
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
      <section className="workspace-intro" aria-labelledby="vault-title">
        <h1 id="vault-title">Bóveda desbloqueada.</h1>
        <button className="primary-button new-credential-button" type="button" onClick={openNewCredentialModal}>
          + Nueva credencial
        </button>
      </section>
      <ChangePasswordPanel
        open={isChangePasswordModalOpen}
        onOpen={openChangePasswordModal}
        onClose={closeChangePasswordModal}
        busy={busy}
        onSubmit={handleChangePassword}
      />
      <VaultHealthPanel credentials={credentials} onEdit={openEditCredentialModal} />
      <div className="vault-layout">
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
              <legend>URLs</legend>
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
                    required
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
        <section
          className="credential-list"
          aria-live="polite"
          aria-labelledby="list-title"
        >
          <div className="section-heading list-heading">
            <h2 id="list-title">
              {credentials.length === 0
                ? "Tu bóveda empieza aquí"
                : "Accesos guardados"}
            </h2>
          </div>
          {credentials.length === 0 && (
            <div className="empty-state">
              <div className="empty-glyph">+</div>
              <p>
                Añade tu primer acceso para tenerlo disponible cuando lo
                necesites, sin exponerlo al servidor.
              </p>
            </div>
          )}
          {credentials.map((item) => {
            const firstUrl = item.urls.find((u) => u.length > 0);
            const faviconUrl = firstUrl ? getFaviconUrl(firstUrl) : null;
            const isAffected = affectedIds.has(item.id);
            const isBreached = breachedIds.has(item.id);
            const hasTotp = Boolean(item.totpSecret);

            return (
              <article className={`credential-card${isAffected ? " credential-card--affected" : ""}`} key={item.id}>
                <div className="credential-card-header">
                  <div className="credential-avatar">
                    {faviconUrl ? (
                      <img
                        className="credential-favicon"
                        src={faviconUrl}
                        alt=""
                        width="20"
                        height="20"
                        onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = "none"; }}
                      />
                    ) : null}
                    <span className={`credential-avatar-fallback${faviconUrl ? " credential-avatar-fallback--hidden" : ""}`}>
                      {item.title.charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <div className="credential-title-group">
                    <h3>{item.title}</h3>
                    <div className="credential-badges">
                      {hasTotp && (
                        <span className="badge badge--2fa">2FA</span>
                      )}
                      {isBreached && (
                        <span className="badge badge--breach">Comprometida</span>
                      )}
                      {!isBreached && isAffected && (
                        <span className="badge badge--weak">Débil</span>
                      )}
                    </div>
                  </div>
                  <div className="item-actions">
                    <button
                      className="action-button"
                      type="button"
                      onClick={async () => { if (await copyToClipboard(item.username)) addToast("Usuario copiado"); }}
                      title="Copiar usuario"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    </button>
                    <button
                      className="action-button"
                      type="button"
                      onClick={() => setRevealedId(revealedId === item.id ? null : item.id)}
                      title={revealedId === item.id ? "Ocultar contraseña" : "Mostrar contraseña"}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">{revealedId === item.id ? (<><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></>) : (<><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></>)}</svg>
                    </button>
                    <button
                      className="action-button"
                      type="button"
                      onClick={async () => { if (await copyToClipboard(item.password)) addToast("Contraseña copiada"); }}
                      title="Copiar contraseña"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    </button>
                    <button
                      className="action-button"
                      type="button"
                      onClick={() => openEditCredentialModal(item.id)}
                      title="Editar"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    </button>
                    <button
                      className="action-button action-button--danger"
                      type="button"
                      onClick={() => setDeletingId(item.id)}
                      disabled={busy}
                      title="Borrar"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                    </button>
                  </div>
                </div>
                <div className="credential-card-body">
                  <p className="credential-username">{item.username}</p>
                  {item.urls.map((url) => (
                    <a key={url} href={url} target="_blank" rel="noreferrer" className="credential-url">
                      {url}
                    </a>
                  ))}
                  <div className="credential-secret-row">
                    <label className="credential-secret-label">Contraseña</label>
                    <input
                      className="password-preview"
                      type={revealedId === item.id ? "text" : "password"}
                      value={item.password}
                      readOnly
                      aria-label={`Contraseña de ${item.title}`}
                    />
                  </div>
                   {item.totpSecret && <TotpCode secret={item.totpSecret} onCopy={() => addToast("Código TOTP copiado")} />}
                </div>
              </article>
            );
          })}
        </section>
      </div>
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
