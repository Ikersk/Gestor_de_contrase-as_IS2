import { useState } from "react";
import type { DecryptedCredential } from "./vault";
import { auditVault } from "./vault-health";
import type { VaultHealthAlert } from "./vault-health";
import { checkCredentialsBreach } from "./hibp";

interface VaultHealthPanelProps {
  credentials: DecryptedCredential[];
  onEdit: (id: number | string) => void;
}

function AlertList({
  alerts,
  onEdit,
}: {
  alerts: VaultHealthAlert[];
  onEdit: (id: number | string) => void;
}) {
  return (
    <ul className="health-alert-list">
      {alerts.map((alert) => (
        <li className="health-alert" key={`${alert.id}-${alert.reason}`}>
          <div>
            <strong>{alert.title}</strong>
            <span>{alert.username}</span>
            <p>{alert.reason}</p>
          </div>
          <button className="health-resolve-button" type="button" onClick={() => onEdit(alert.id)}>
            Resolver
          </button>
        </li>
      ))}
    </ul>
  );
}

export function VaultHealthPanel({ credentials, onEdit }: VaultHealthPanelProps) {
  const [breachedAlerts, setBreachedAlerts] = useState<VaultHealthAlert[]>([]);
  const [isChecking, setIsChecking] = useState(false);
  const [checkedCount, setCheckedCount] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const report = auditVault(credentials, breachedAlerts);
  const isHealthy = report.reused.length === 0 && report.weak.length === 0 && report.breached.length === 0;

  async function handleCheckBreach() {
    setIsChecking(true);
    setCheckedCount(0);
    setError(null);

    try {
      const alerts = await checkCredentialsBreach(credentials, (checked) => {
        setCheckedCount(checked);
      });
      setBreachedAlerts(alerts);
    } catch {
      setError("No se pudo conectar con Have I Been Pwned. Inténtalo de nuevo.");
    } finally {
      setIsChecking(false);
    }
  }

  return (
    <section className="vault-health" aria-labelledby="vault-health-title">
      <div className="health-header">
        <div>
          <p className="eyebrow">Revisión local</p>
          <h2 id="vault-health-title">Salud de la bóveda</h2>
          <p className="health-description">
            Un diagnóstico privado de tus accesos descifrados en este dispositivo.
          </p>
        </div>
        <div className="health-score" aria-label={`Puntaje de salud: ${report.score}%`}>
          <strong>{report.score}%</strong>
          <span>Puntaje</span>
        </div>
      </div>
      <div
        className="health-progress"
        role="progressbar"
        aria-label="Puntaje de Salud de la Bóveda"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={report.score}
      >
        <span style={{ transform: `scaleX(${report.score / 100})` }} />
      </div>
      <div className="health-summary">
        <span className={report.reused.length > 0 ? "health-stat warning" : "health-stat"}>
          <strong>{report.reused.length}</strong> reutilizadas
        </span>
        <span className={report.weak.length > 0 ? "health-stat warning" : "health-stat"}>
          <strong>{report.weak.length}</strong> débiles
        </span>
        <span className={report.breached.length > 0 ? "health-stat warning" : "health-stat"}>
          <strong>{report.breached.length}</strong> filtradas
        </span>
      </div>

      <div className="health-breach-check">
        {isChecking ? (
          <div className="breach-progress">
            <span>Comprobando filtraciones... {checkedCount}/{credentials.length}</span>
            <div className="breach-progress-bar">
              <span
                style={{
                  transform: `scaleX(${credentials.length > 0 ? checkedCount / credentials.length : 0})`,
                }}
              />
            </div>
          </div>
        ) : (
          <button
            className="health-resolve-button breach-check-button"
            type="button"
            onClick={handleCheckBreach}
            disabled={credentials.length === 0}
          >
            Comprobar filtraciones
          </button>
        )}
        {error && <p className="breach-error">{error}</p>}
      </div>

      {isHealthy ? (
        <p className="health-empty" role="status">
          {credentials.length === 0
            ? "Añade un acceso para iniciar la revisión."
            : "No encontramos problemas en tus accesos."}
        </p>
      ) : (
        <div className="health-alerts">
          {report.reused.length > 0 && (
            <div className="health-alert-group">
              <h3>Contraseñas reutilizadas</h3>
              <AlertList alerts={report.reused} onEdit={onEdit} />
            </div>
          )}
          {report.weak.length > 0 && (
            <div className="health-alert-group">
              <h3>Contraseñas débiles</h3>
              <AlertList alerts={report.weak} onEdit={onEdit} />
            </div>
          )}
          {report.breached.length > 0 && (
            <div className="health-alert-group">
              <h3>Contraseñas comprometidas</h3>
              <AlertList alerts={report.breached} onEdit={onEdit} />
            </div>
          )}
        </div>
      )}
    </section>
  );
}
