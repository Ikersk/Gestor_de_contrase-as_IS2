import { FormEvent, StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  loginWithMasterPassword,
  logoutFromMemory,
  registerWithMasterPassword,
} from './auth';
import './styles.css';

type View = 'login' | 'register';

// Interfaz de Fase 3: las credenciales se usan para derivar claves y se descartan al terminar.
function App() {
  const [view, setView] = useState<View>('login');
  const [email, setEmail] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [authenticated, setAuthenticated] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setMessage('');

    try {
      if (view === 'register') {
        await registerWithMasterPassword(email, masterPassword);
        setView('login');
        setMessage('Cuenta creada. Inicia sesion para abrir tu boveda.');
      } else {
        await loginWithMasterPassword(email, masterPassword);
        setAuthenticated(true);
        setMessage('Boveda desbloqueada en memoria.');
      }
      setMasterPassword('');
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'No se pudo completar la operacion');
    } finally {
      setBusy(false);
    }
  }

  async function handleLogout() {
    setBusy(true);
    setError('');
    try {
      await logoutFromMemory();
      setAuthenticated(false);
      setMessage('Sesion cerrada.');
    } catch (logoutError) {
      setError(logoutError instanceof Error ? logoutError.message : 'No se pudo cerrar la sesion');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <section className="intro" aria-labelledby="app-title">
        <div className="mark" aria-hidden="true">A</div>
        <p className="eyebrow">Boveda privada</p>
        <h1 id="app-title">Tu acceso, bajo tu control.</h1>
        <p className="summary">
          Tus claves nacen en este dispositivo. El servidor solo recibe
          material derivado y datos cifrados.
        </p>
      </section>

      <section className="status-panel" aria-labelledby="status-title">
        {authenticated ? (
          <div className="unlocked-state">
            <div className="status-heading">
              <span className="status-dot" aria-hidden="true" />
              <div>
                <p className="eyebrow">Sesion activa</p>
                <h2 id="status-title">Boveda desbloqueada</h2>
              </div>
            </div>
            <p>La Vault Key permanece en memoria y esta lista para la siguiente fase.</p>
            <button className="button button-secondary" type="button" onClick={handleLogout} disabled={busy}>
              {busy ? 'Cerrando...' : 'Cerrar sesion'}
            </button>
          </div>
        ) : (
          <>
            <div className="status-heading">
              <span className="status-dot" aria-hidden="true" />
              <div>
                <p className="eyebrow">Acceso seguro</p>
                <h2 id="status-title">{view === 'login' ? 'Abrir la boveda' : 'Crear tu boveda'}</h2>
              </div>
            </div>

            <div className="mode-switch" role="tablist" aria-label="Modo de acceso">
              <button
                className={view === 'login' ? 'mode-button active' : 'mode-button'}
                type="button"
                role="tab"
                aria-selected={view === 'login'}
                onClick={() => { setView('login'); setError(''); setMessage(''); }}
              >
                Iniciar sesion
              </button>
              <button
                className={view === 'register' ? 'mode-button active' : 'mode-button'}
                type="button"
                role="tab"
                aria-selected={view === 'register'}
                onClick={() => { setView('register'); setError(''); setMessage(''); }}
              >
                Crear cuenta
              </button>
            </div>

            <form className="auth-form" onSubmit={handleSubmit}>
              <label htmlFor="email">Correo electronico</label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
              <label htmlFor="master-password">Contrasena maestra</label>
              <input
                id="master-password"
                type="password"
                autoComplete={view === 'login' ? 'current-password' : 'new-password'}
                value={masterPassword}
                onChange={(event) => setMasterPassword(event.target.value)}
                minLength={12}
                required
              />
              <button className="button" type="submit" disabled={busy}>
                {busy ? 'Procesando...' : view === 'login' ? 'Desbloquear' : 'Crear boveda'}
              </button>
            </form>

            <p className="form-note">Nunca enviamos tu contrasena maestra.</p>
            {message && <p className="feedback success" role="status">{message}</p>}
            {error && <p className="feedback error" role="alert">{error}</p>}
          </>
        )}
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
