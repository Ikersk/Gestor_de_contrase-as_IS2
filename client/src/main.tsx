import { FormEvent, StrictMode, useEffect, useState } from "react";
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

type View = "login" | "register";
// Estado inicial reutilizado al abrir el formulario y al limpiar una credencial.
const emptyCredential: Credential = {
  title: "",
  username: "",
  password: "",
  urls: [""],
};

function TotpCode({ secret }: { secret: string }) {
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
    } catch {
      setError("No se pudo copiar el código");
    }
  }

  if (error) return <p className="totp-error" role="status">{error}</p>;
  if (!snapshot) return <p className="totp-loading" role="status">Calculando código...</p>;

  return (
    <div className="totp-panel" aria-label="Código de autenticación de dos factores">
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
      <div className="totp-progress" role="progressbar" aria-label="Tiempo restante del código" aria-valuemin={0} aria-valuemax={30} aria-valuenow={snapshot.remainingSeconds}>
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
  busy,
  onSubmit,
}: {
  busy: boolean;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <section className="account-panel" aria-labelledby="change-password-title">
      <div className="section-heading">
        <h2 id="change-password-title">Cambiar contraseña maestra</h2>
      </div>
      <form className="credential-form" onSubmit={onSubmit}>
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

/** Coordina la navegación, la sesión en memoria y las operaciones CRUD de la bóveda. */
function App() {
  const [view, setView] = useState<View>("login");
  const [showAccess, setShowAccess] = useState(false);
  const [email, setEmail] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [authenticated, setAuthenticated] = useState(false);
  const [credentials, setCredentials] = useState<
    Array<Credential & { id: number | string }>
  >([]);
  const [credential, setCredential] = useState<Credential>(emptyCredential);
  const [editingId, setEditingId] = useState<number | string | null>(null);
  const [revealedId, setRevealedId] = useState<number | string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

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
        setCredentials(await listCredentials());
        setAuthenticated(true);
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
      setCredentials([]);
      setCredential(emptyCredential);
      setEditingId(null);
      setRevealedId(null);
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
      setCredentials([]);
      setCredential(emptyCredential);
      setEditingId(null);
      setRevealedId(null);
      setView("login");
      setShowAccess(true);
      setMessage("Contraseña actualizada. Inicia sesión de nuevo.");
      event.currentTarget.reset();
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
  /** Elimina una credencial en el servidor y sincroniza la lista local. */
  async function handleDelete(id: number | string) {
    setBusy(true);
    setError("");
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
          <button
            className="back-link"
            type="button"
            onClick={() => setShowAccess(false)}
          >
            Volver al inicio
          </button>
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
        <button
          className="text-button"
          type="button"
          onClick={handleLogout}
          disabled={busy}
        >
          {busy ? "Cerrando..." : "Cerrar sesión"}
        </button>
      </header>
      <section className="workspace-intro" aria-labelledby="vault-title">
        <h1 id="vault-title">Bóveda desbloqueada.</h1>
      </section>
      <ChangePasswordPanel busy={busy} onSubmit={handleChangePassword} />
      <div className="vault-layout">
        <section className="vault-composer" aria-labelledby="composer-title">
          <div className="section-heading">
            <h2 id="composer-title">
              {editingId === null ? "Guardar un acceso" : "Actualizar acceso"}
            </h2>
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
              {editingId !== null && (
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => {
                    setEditingId(null);
                    setCredential(emptyCredential);
                  }}
                >
                  Cancelar
                </button>
              )}
            </div>
          </form>
        </section>
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
          {credentials.map((item) => (
            <article className="credential-item" key={item.id}>
              <div className="credential-avatar">
                {item.title.charAt(0).toUpperCase()}
              </div>
              <div className="credential-details">
                <h3>{item.title}</h3>
                <p>{item.username}</p>
                {item.urls.map((url) => (
                  <a key={url} href={url} target="_blank" rel="noreferrer">
                    {url}
                  </a>
                ))}
                <input
                  className="password-preview"
                  type={revealedId === item.id ? "text" : "password"}
                  value={item.password}
                  readOnly
                  aria-label={`Contraseña de ${item.title}`}
                />
                {item.totpSecret && <TotpCode secret={item.totpSecret} />}
              </div>
              <div className="item-actions">
                <button
                  type="button"
                  onClick={() =>
                    setRevealedId(revealedId === item.id ? null : item.id)
                  }
                >
                  {revealedId === item.id ? "Ocultar" : "Mostrar"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setEditingId(item.id);
                    setCredential(item);
                  }}
                >
                  Editar
                </button>
                <button
                  type="button"
                  onClick={() => handleDelete(item.id)}
                  disabled={busy}
                >
                  Borrar
                </button>
              </div>
            </article>
          ))}
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
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
