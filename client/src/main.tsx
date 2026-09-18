import { FormEvent, StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { loginWithMasterPassword, logoutFromMemory, registerWithMasterPassword } from './auth';
import { Credential, createCredential, listCredentials, removeCredential, updateCredential } from './vault';
import './styles.css';
import { FIELD_LIMITS } from './validation';

type View = 'login' | 'register';
const emptyCredential: Credential = { title: '', username: '', password: '', url: '' };

function AuthPanel({ view, setView, email, setEmail, masterPassword, setMasterPassword, busy, message, error, onSubmit }: {
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
  return <section className="auth-card" aria-labelledby="auth-title">
    <div className="auth-card-top"><span className="live-indicator" aria-hidden="true" /> <span>Acceso privado</span></div>
    <p className="kicker">{view === 'login' ? 'Vuelve a tus accesos' : 'Tu espacio empieza aquí'}</p>
    <h2 id="auth-title">{view === 'login' ? 'Abre tu bóveda' : 'Crea tu bóveda'}</h2>
    <div className="auth-tabs" role="tablist" aria-label="Tipo de acceso">
      <button className={view === 'login' ? 'auth-tab active' : 'auth-tab'} type="button" role="tab" aria-selected={view === 'login'} onClick={() => setView('login')}>Iniciar sesión</button>
      <button className={view === 'register' ? 'auth-tab active' : 'auth-tab'} type="button" role="tab" aria-selected={view === 'register'} onClick={() => setView('register')}>Crear cuenta</button>
    </div>
    <form className="auth-form" onSubmit={onSubmit}>
      <label htmlFor="email">Correo electrónico</label>
      <input id="email" type="email" maxLength={FIELD_LIMITS.email} autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
      <label htmlFor="master-password">Contraseña maestra</label>
      <input id="master-password" type="password" maxLength={FIELD_LIMITS.masterPassword} minLength={12} autoComplete={view === 'login' ? 'current-password' : 'new-password'} value={masterPassword} onChange={(event) => setMasterPassword(event.target.value)} required />
      <button className="primary-button" type="submit" disabled={busy}>{busy ? 'Procesando...' : view === 'login' ? 'Desbloquear bóveda' : 'Crear bóveda'}</button>
    </form>
    <p className="auth-note"><span aria-hidden="true">✦</span> La contraseña maestra nunca sale de tu dispositivo.</p>
    {message && <p className="feedback success" role="status">{message}</p>}
    {error && <p className="feedback error" role="alert">{error}</p>}
  </section>;
}

function Landing({ onAccess }: { onAccess: () => void }) {
  return <div className="landing-page">
    <header className="site-header">
      <a className="brand" href="/" aria-label="Arca, inicio"><span className="brand-symbol">A</span><span>arca</span></a>
      <nav className="site-nav" aria-label="Navegación principal"><a href="#principios">Principios</a><button type="button" onClick={onAccess}>Entrar</button></nav>
    </header>
    <main>
      <section className="hero-section" aria-labelledby="hero-title">
        <div className="hero-copy">
          <p className="kicker">Gestor de accesos zero knowledge</p>
          <h1 id="hero-title">Tus accesos,<br /><span>bajo tus reglas.</span></h1>
          <p className="hero-description">Arca cifra tus credenciales en tu dispositivo para que puedas guardar lo importante sin entregar tus secretos a nadie.</p>
          <div className="hero-actions"><button className="primary-button" type="button" onClick={onAccess}>Crear mi bóveda <span aria-hidden="true">↗</span></button><span className="risk-note">Gratis para empezar <span aria-hidden="true">·</span> Sin tarjeta</span></div>
        </div>
        <div className="vault-art" aria-label="Diagrama de cifrado local">
          <div className="vault-art-grid" aria-hidden="true" />
          <div className="vault-core"><span className="core-mark">A</span><span className="core-label">BÓVEDA</span></div>
          <span className="orbit-label label-top">TU CLAVE MAESTRA</span><span className="orbit-label label-right">ENCRIPTACIÓN</span><span className="orbit-label label-bottom">SOLO TÚ</span>
          <span className="orbit-label secondary-label secondary-top">SEGURIDAD</span><span className="orbit-label secondary-label secondary-right">SECRETOS</span><span className="orbit-label secondary-label secondary-bottom">CIFRADO</span>
          <div className="orbit-line orbit-line-one" aria-hidden="true" /><div className="orbit-line orbit-line-two" aria-hidden="true" />
        </div>
      </section>
      <section className="signal-bar" aria-label="Principios de seguridad"><span><i className="signal-dot" /> Cifrado local</span><span>Tu clave nunca se almacena</span><span>Sesiones temporales</span></section>
      <section className="principles-section" id="principios" aria-labelledby="principles-title">
        <div className="section-intro"><p className="kicker">La diferencia está en dónde ocurre</p><h2 id="principles-title">Privacidad que se puede explicar.</h2><p>No necesitas confiar a ciegas. Arca está diseñada para que el recorrido de tus credenciales sea fácil de entender.</p></div>
        <div className="principles-grid"><article><span className="principle-index">01</span><h3>Se cifra antes de salir</h3><p>Tu contraseña maestra deriva las claves en el navegador. El servidor recibe únicamente material cifrado.</p></article><article><span className="principle-index">02</span><h3>Se descifra cuando hace falta</h3><p>La bóveda solo se abre en una sesión activa y la clave desaparece al cerrarla.</p></article><article><span className="principle-index">03</span><h3>Se organiza sin ruido</h3><p>Guarda nombres, usuarios, contraseñas y URLs en una vista pensada para volver cada día.</p></article></div>
      </section>
      <section className="faq-section" aria-labelledby="faq-title"><div className="section-intro"><p className="kicker">Preguntas honestas</p><h2 id="faq-title">Lo que necesitas saber antes de empezar.</h2></div><div className="faq-list"><details><summary>¿Puede Arca ver mis contraseñas?</summary><p>No. Tus credenciales se cifran en el dispositivo y el servidor no recibe los valores legibles.</p></details><details><summary>¿Qué ocurre si olvido mi contraseña maestra?</summary><p>No existe una copia de recuperación. Es la consecuencia de que nadie más pueda abrir tu bóveda.</p></details><details><summary>¿Tiene coste crear una cuenta?</summary><p>No. Puedes crear una cuenta y probar la bóveda sin tarjeta.</p></details></div></section>
      <section className="closing-section"><div><p className="kicker">Empieza con una decisión</p><h2>Menos exposición.<br />Más control.</h2></div><button className="primary-button light-button" type="button" onClick={onAccess}>Abrir mi bóveda <span aria-hidden="true">↗</span></button></section>
    </main>
    <footer className="site-footer"><span>arca / privacidad primero</span><span>Construido para guardar lo importante</span></footer>
  </div>;
}

function App() {
  const [view, setView] = useState<View>('login');
  const [showAccess, setShowAccess] = useState(false);
  const [email, setEmail] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [authenticated, setAuthenticated] = useState(false);
  const [credentials, setCredentials] = useState<Array<Credential & { id: number | string }>>([]);
  const [credential, setCredential] = useState<Credential>(emptyCredential);
  const [editingId, setEditingId] = useState<number | string | null>(null);
  const [revealedId, setRevealedId] = useState<number | string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(''); setMessage('');
    try {
      if (view === 'register') { await registerWithMasterPassword(email, masterPassword); setView('login'); setMessage('Cuenta creada. Inicia sesión para abrir tu bóveda.'); }
      else { await loginWithMasterPassword(email, masterPassword); setCredentials(await listCredentials()); setAuthenticated(true); setMessage('Bóveda desbloqueada en memoria.'); }
      setMasterPassword('');
    } catch (submitError) { setError(submitError instanceof Error ? submitError.message : 'No se pudo completar la operación'); }
    finally { setBusy(false); }
  }
  async function handleLogout() {
    setBusy(true); setError('');
    try { await logoutFromMemory(); setMessage('Sesión cerrada.'); }
    catch (logoutError) { setError(logoutError instanceof Error ? logoutError.message : 'No se pudo cerrar la sesión'); }
    finally { setAuthenticated(false); setCredentials([]); setCredential(emptyCredential); setEditingId(null); setRevealedId(null); setBusy(false); }
  }
  async function handleCredentialSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      if (editingId === null) { const created = await createCredential(credential); setCredentials((current) => [...current, created]); setMessage('Credencial cifrada y guardada.'); }
      else { const updated = await updateCredential(editingId, credential); setCredentials((current) => current.map((item) => item.id === editingId ? updated : item)); setMessage('Credencial actualizada.'); }
      setCredential(emptyCredential); setEditingId(null);
    } catch (saveError) { setError(saveError instanceof Error ? saveError.message : 'No se pudo guardar la credencial'); }
    finally { setBusy(false); }
  }
  async function handleDelete(id: number | string) {
    setBusy(true); setError('');
    try { await removeCredential(id); setCredentials((current) => current.filter((item) => item.id !== id)); if (editingId === id) { setCredential(emptyCredential); setEditingId(null); } setMessage('Credencial eliminada.'); }
    catch (deleteError) { setError(deleteError instanceof Error ? deleteError.message : 'No se pudo eliminar la credencial'); }
    finally { setBusy(false); }
  }

  if (!authenticated && !showAccess) return <Landing onAccess={() => { setShowAccess(true); setView('register'); }} />;
  if (!authenticated) return <main className="auth-page"><header className="site-header"><a className="brand" href="/" aria-label="Arca, inicio"><span className="brand-symbol">A</span><span>arca</span></a><button className="back-link" type="button" onClick={() => setShowAccess(false)}>Volver al inicio</button></header><AuthPanel view={view} setView={(nextView) => { setView(nextView); setError(''); setMessage(''); }} email={email} setEmail={setEmail} masterPassword={masterPassword} setMasterPassword={setMasterPassword} busy={busy} message={message} error={error} onSubmit={handleSubmit} /></main>;

  return <main className="app-shell vault-shell"><header className="workspace-header"><a className="brand" href="/" aria-label="Arca, inicio"><span className="brand-symbol">A</span><span>arca</span></a><button className="text-button" type="button" onClick={handleLogout} disabled={busy}>{busy ? 'Cerrando...' : 'Cerrar sesión'}</button></header><section className="workspace-intro" aria-labelledby="vault-title"><h1 id="vault-title">Bóveda desbloqueada.</h1></section><div className="vault-layout"><section className="vault-composer" aria-labelledby="composer-title"><div className="section-heading"><h2 id="composer-title">{editingId === null ? 'Guardar un acceso' : 'Actualizar acceso'}</h2></div><form className="credential-form" onSubmit={handleCredentialSubmit}><label htmlFor="credential-title">Nombre</label><input id="credential-title" maxLength={FIELD_LIMITS.title} placeholder="Ej. GitHub" value={credential.title} onChange={(event) => setCredential({ ...credential, title: event.target.value })} required /><label htmlFor="credential-username">Usuario</label><input id="credential-username" maxLength={FIELD_LIMITS.username} autoComplete="off" placeholder="Tu nombre de usuario" value={credential.username} onChange={(event) => setCredential({ ...credential, username: event.target.value })} required /><label htmlFor="credential-password">Contraseña</label><input id="credential-password" maxLength={FIELD_LIMITS.password} type="password" autoComplete="new-password" placeholder="Contraseña del acceso" value={credential.password} onChange={(event) => setCredential({ ...credential, password: event.target.value })} required /><label htmlFor="credential-url">URL <span>Opcional</span></label><input id="credential-url" maxLength={FIELD_LIMITS.url} type="url" autoComplete="off" placeholder="https://" value={credential.url} onChange={(event) => setCredential({ ...credential, url: event.target.value })} /><div className="form-actions"><button className="primary-button" type="submit" disabled={busy}>{editingId === null ? 'Guardar acceso' : 'Guardar cambios'}</button>{editingId !== null && <button className="secondary-button" type="button" onClick={() => { setEditingId(null); setCredential(emptyCredential); }}>Cancelar</button>}</div></form></section><section className="credential-list" aria-live="polite" aria-labelledby="list-title"><div className="section-heading list-heading"><h2 id="list-title">{credentials.length === 0 ? 'Tu bóveda empieza aquí' : 'Accesos guardados'}</h2></div>{credentials.length === 0 && <div className="empty-state"><div className="empty-glyph">+</div><p>Añade tu primer acceso para tenerlo disponible cuando lo necesites, sin exponerlo al servidor.</p></div>}{credentials.map((item) => <article className="credential-item" key={item.id}><div className="credential-avatar">{item.title.charAt(0).toUpperCase()}</div><div className="credential-details"><h3>{item.title}</h3><p>{item.username}</p>{item.url && <a href={item.url} target="_blank" rel="noreferrer">{item.url}</a>}<input className="password-preview" type={revealedId === item.id ? 'text' : 'password'} value={item.password} readOnly aria-label={`Contraseña de ${item.title}`} /></div><div className="item-actions"><button type="button" onClick={() => setRevealedId(revealedId === item.id ? null : item.id)}>{revealedId === item.id ? 'Ocultar' : 'Mostrar'}</button><button type="button" onClick={() => { setEditingId(item.id); setCredential(item); }}>Editar</button><button type="button" onClick={() => handleDelete(item.id)} disabled={busy}>Borrar</button></div></article>)}</section></div>{message && <p className="feedback success" role="status">{message}</p>}{error && <p className="feedback error" role="alert">{error}</p>}</main>;
}

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
