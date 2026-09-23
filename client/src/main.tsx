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
import "./landing/landing.css";
import "./styles.css";
import { Landing } from "./landing/Landing";
import { TextureLayers } from "./landing/TextureLayers";
import { ThemeSwitcher } from "./ThemeSwitcher";
import { FIELD_LIMITS } from "./validation";
import {
  DEFAULT_PASSWORD_CHARACTER_SELECTION,
  generateSecurePassword,
  PASSWORD_GENERATOR_DEFAULT_LENGTH,
  PASSWORD_GENERATOR_MAX_LENGTH,
  PASSWORD_GENERATOR_MIN_LENGTH,
  PasswordCharacterOption,
} from "./password-generator";
import { auditVault } from "./vault-health";
import type { VaultHealthAlert } from "./vault-health";
import { checkCredentialsBreach } from "./hibp";
import { VaultShell } from "./vault/VaultShell";

type View = "login" | "register";
type Toast = { id: number; message: string; type: "success" | "error"; exiting?: boolean };

// Estado inicial reutilizado al abrir el formulario y al limpiar una credencial.
const emptyCredential: Credential = {
  title: "",
  username: "",
  password: "",
  urls: [""],
  favorite: false,
};

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
  confirmMasterPassword,
  setConfirmMasterPassword,
  showMasterPassword,
  setShowMasterPassword,
  showConfirmMasterPassword,
  setShowConfirmMasterPassword,
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
  confirmMasterPassword: string;
  setConfirmMasterPassword: (value: string) => void;
  showMasterPassword: boolean;
  setShowMasterPassword: (value: boolean) => void;
  showConfirmMasterPassword: boolean;
  setShowConfirmMasterPassword: (value: boolean) => void;
  busy: boolean;
  message: string;
  error: string;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const isRegister = view === "register";
  const confirmDirty = confirmMasterPassword.length > 0;
  const passwordsMatch = confirmDirty && masterPassword === confirmMasterPassword;
  const passwordsMismatch = confirmDirty && masterPassword !== confirmMasterPassword;
  const submitDisabled = busy || (isRegister && confirmDirty && !passwordsMatch);

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
          onClick={() => {
            setView("login");
            setConfirmMasterPassword("");
            setShowMasterPassword(false);
            setShowConfirmMasterPassword(false);
          }}
        >
          Iniciar sesión
        </button>
        <button
          className={view === "register" ? "auth-tab active" : "auth-tab"}
          type="button"
          role="tab"
          aria-selected={view === "register"}
          onClick={() => {
            setView("register");
            setConfirmMasterPassword("");
            setShowMasterPassword(false);
            setShowConfirmMasterPassword(false);
          }}
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
        <div className="auth-password-wrapper">
          <input
            id="master-password"
            type={showMasterPassword ? "text" : "password"}
            maxLength={FIELD_LIMITS.masterPassword}
            minLength={12}
            autoComplete={view === "login" ? "current-password" : "new-password"}
            value={masterPassword}
            onChange={(event) => setMasterPassword(event.target.value)}
            required
          />
          <button
            className="auth-eye-button"
            type="button"
            tabIndex={-1}
            onClick={() => setShowMasterPassword(!showMasterPassword)}
            aria-label={showMasterPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
          >
            {showMasterPassword ? (
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
        </div>
        {isRegister && (
          <>
            <label htmlFor="confirm-master-password">Confirmar contraseña maestra</label>
            <div className="auth-password-wrapper">
              <input
                id="confirm-master-password"
                type={showConfirmMasterPassword ? "text" : "password"}
                maxLength={FIELD_LIMITS.masterPassword}
                minLength={12}
                autoComplete="new-password"
                className={
                  passwordsMatch
                    ? "confirm-input--valid"
                    : passwordsMismatch
                      ? "confirm-input--error"
                      : ""
                }
                value={confirmMasterPassword}
                onChange={(event) => setConfirmMasterPassword(event.target.value)}
                required
              />
              <button
                className="auth-eye-button"
                type="button"
                tabIndex={-1}
                onClick={() => setShowConfirmMasterPassword(!showConfirmMasterPassword)}
                aria-label={showConfirmMasterPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
              >
                {showConfirmMasterPassword ? (
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
            </div>
            {passwordsMatch && (
              <p className="confirm-hint confirm-hint--success">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M20 6 9 17l-5-5"/>
                </svg>
                Las contraseñas coinciden
              </p>
            )}
            {passwordsMismatch && (
              <p className="confirm-hint confirm-hint--error">
                Las contraseñas no coinciden
              </p>
            )}
          </>
        )}
        <button className="primary-button" type="submit" disabled={submitDisabled}>
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
  const [breachError, setBreachError] = useState<string | null>(null);
  const [deletePassword, setDeletePassword] = useState("");
  const [isDeletingAccount, setIsDeletingAccount] = useState(false);
  const [confirmMasterPassword, setConfirmMasterPassword] = useState("");
  const [showMasterPassword, setShowMasterPassword] = useState(false);
  const [showConfirmMasterPassword, setShowConfirmMasterPassword] = useState(false);

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
    setBreachError(null);

    try {
      const alerts = await checkCredentialsBreach(credentials);
      setBreachedAlerts(alerts);
    } catch {
      setBreachError("No se pudo conectar con Have I Been Pwned. Inténtalo de nuevo.");
    } finally {
      setIsCheckingBreach(false);
    }
  }

  useEffect(() => {
    if (authenticated && !decrypting && credentials.length > 0 && breachedAlerts.length === 0 && !isCheckingBreach) {
      handleCheckBreach();
    }
  }, [authenticated, decrypting, credentials.length]);

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
        if (masterPassword !== confirmMasterPassword) {
          addToast("Las contraseñas no coinciden", "error");
          return;
        }
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
      setConfirmMasterPassword("");
      setShowMasterPassword(false);
      setShowConfirmMasterPassword(false);
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
      setBreachError(null);
      setSelectedCredentialId(null);
      setConfirmMasterPassword("");
      setShowMasterPassword(false);
      setShowConfirmMasterPassword(false);
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

  /** Alterna el favorito cifrando de nuevo el blob completo. */
  async function handleToggleFavorite(id: number | string) {
    const item = credentials.find((c) => c.id === id);
    if (!item) return;
    try {
      const updated = await updateCredential(id, {
        ...item,
        favorite: !item.favorite,
      });
      setCredentials((current) =>
        current.map((c) => (c.id === id ? updated : c)),
      );
    } catch (favError) {
      addToast(
        favError instanceof Error ? favError.message : "No se pudo actualizar el favorito",
        "error",
      );
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
      <main className="landing-page relative isolate">
        <TextureLayers />
        <div className="relative z-10 min-h-screen">
          <div className="relative z-20 w-full border-b border-line bg-[var(--lp-topbar)]">
            <header className="mx-auto flex w-full max-w-6xl items-center justify-between gap-6 px-6 py-6">
              <a
                className="group inline-flex items-center gap-2.5 font-display text-[17px] font-semibold tracking-[0.2em] uppercase text-ink"
                href="/"
                aria-label="Arca, inicio"
              >
                <span className="grid h-8 w-8 place-items-center rounded-md bg-blue-electric font-mono text-[13px] font-bold tracking-normal text-abyss shadow-[0_0_18px_rgba(37,99,235,0.45)] transition-shadow group-hover:shadow-[0_0_28px_rgba(37,99,235,0.7)]">
                  A
                </span>
                arca
              </a>
              <nav className="flex items-center gap-7 font-mono text-[11px] uppercase tracking-[0.16em] text-ink-dim" aria-label="Navegación">
                <button
                  className="rounded-full border border-line px-4 py-1.5 text-ink transition hover:border-glow hover:text-blue-electric"
                  type="button"
                  onClick={() => setShowAccess(false)}
                >
                  Volver al inicio
                </button>
                <ThemeSwitcher />
              </nav>
            </header>
          </div>
          <div className="auth-page">
            <AuthPanel
              view={view}
              setView={(nextView) => {
                setView(nextView);
                setError("");
                setMessage("");
                setConfirmMasterPassword("");
                setShowMasterPassword(false);
                setShowConfirmMasterPassword(false);
              }}
              email={email}
              setEmail={setEmail}
              masterPassword={masterPassword}
              setMasterPassword={setMasterPassword}
              confirmMasterPassword={confirmMasterPassword}
              setConfirmMasterPassword={setConfirmMasterPassword}
              showMasterPassword={showMasterPassword}
              setShowMasterPassword={setShowMasterPassword}
              showConfirmMasterPassword={showConfirmMasterPassword}
              setShowConfirmMasterPassword={setShowConfirmMasterPassword}
              busy={busy}
              message={message}
              error={error}
              onSubmit={handleSubmit}
            />
          </div>
        </div>
      </main>
    );

  return (
    <VaultShell
      decrypting={decrypting}
      credentials={credentials}
      selectedCredentialId={selectedCredentialId}
      healthReport={healthReport}
      affectedIds={affectedIds}
      breachedIds={breachedIds}
      breachError={breachError}
      isCheckingBreach={isCheckingBreach}
      busy={busy}
      onSelectCredential={setSelectedCredentialId}
      onToggleFavorite={handleToggleFavorite}
      onCheckBreach={handleCheckBreach}
      onLogout={handleLogout}
      onOpenAccount={openAccountModal}
      onOpenNew={openNewCredentialModal}
      onOpenEdit={openEditCredentialModal}
      onRequestDelete={setDeletingId}
    >
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
      <div className="toast-container" aria-live="polite">
        {toasts.map((t) => (
          <div className={`toast toast--${t.type}${t.exiting ? " toast--exit" : ""}`} key={t.id}>
            <svg className="toast-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
            <span className="toast-message">{t.message}</span>
            <div className="toast-progress"><span /></div>
          </div>
        ))}
      </div>
    </VaultShell>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
