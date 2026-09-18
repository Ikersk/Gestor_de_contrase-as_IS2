import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

function App() {
  return (
    <main className="shell">
      <section className="intro" aria-labelledby="app-title">
        <div className="mark" aria-hidden="true">A</div>
        <p className="eyebrow">Boveda privada</p>
        <h1 id="app-title">Tu acceso, bajo tu control.</h1>
        <p className="summary">
          Una base segura para guardar tus credenciales con una arquitectura
          zero-knowledge.
        </p>
      </section>

      <section className="status-panel" aria-labelledby="status-title">
        <div className="status-heading">
          <span className="status-dot" aria-hidden="true" />
          <div>
            <p className="eyebrow">Estado del sistema</p>
            <h2 id="status-title">Cliente listo</h2>
          </div>
        </div>
        <p>
          La interfaz esta preparada. La boveda cifrada se habilitara en las
          siguientes fases del proyecto.
        </p>
        <div className="status-meta">
          <span>Fase 0</span>
          <span>Scaffolding activo</span>
        </div>
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
