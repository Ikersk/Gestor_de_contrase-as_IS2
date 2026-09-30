import { FormEvent, useState } from "react";
import { validateMfaCode } from "./validation";

/**
 * Paso final del login cuando la cuenta exige MFA.
 * Pide el código TOTP de la app de autenticación o un código de respaldo y
 * delega la verificación en el padre, que conserva el reto pendiente en memoria.
 */
export function MfaChallenge({
  email,
  busy,
  error,
  onVerify,
  onBack,
}: {
  email: string;
  busy: boolean;
  error: string;
  onVerify: (code: string) => void;
  onBack: () => void;
}) {
  const [code, setCode] = useState("");
  const invalid = validateMfaCode(code.trim()) !== null;

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || invalid) return;
    onVerify(code.trim());
  }

  function handleChange(value: string) {
    setCode(value);
    // Auto-envío: al completar (o pegar) los 6 dígitos se verifica sin más clics.
    if (!busy && /^\d{6}$/.test(value.trim())) onVerify(value.trim());
  }

  return (
    <section className="auth-card mfa-challenge" aria-labelledby="mfa-challenge-title">
      <div className="auth-card-top">
        <span className="live-indicator" aria-hidden="true" />{" "}
        <span>Segundo factor</span>
      </div>
      <p className="kicker">{email}</p>
      <h2 id="mfa-challenge-title">Verificación en dos pasos</h2>
      <form className="auth-form" onSubmit={handleSubmit}>
        <label htmlFor="mfa-challenge-code">Código de verificación</label>
        <input
          id="mfa-challenge-code"
          className="mfa-code-input"
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={9}
          placeholder="123456"
          value={code}
          onChange={(event) => handleChange(event.target.value)}
          autoFocus
          required
        />
        <button className="primary-button" type="submit" disabled={busy || invalid}>
          {busy ? "Verificando..." : "Verificar y abrir bóveda"}
        </button>
      </form>
      <button
        className="secondary-button mfa-back-button"
        type="button"
        onClick={onBack}
        disabled={busy}
      >
        Volver al inicio de sesión
      </button>
      <p className="auth-note">
        <span aria-hidden="true">✦</span> Introduce el código de tu app de
        autenticación o uno de tus códigos de respaldo.
      </p>
      {error && (
        <p className="feedback error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
