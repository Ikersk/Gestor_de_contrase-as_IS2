import type { DecryptedCredential } from "./vault";
import { auditVault } from "./vault-health";

interface VaultHealthPanelProps {
  credentials: DecryptedCredential[];
  onEdit: (id: number | string) => void;
}

function AlertList({
  alerts,
  onEdit,
}: {
  alerts: ReturnType<typeof auditVault>["reused"];
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
  const report = auditVault(credentials);
  const isHealthy = report.reused.length === 0 && report.weak.length === 0;

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
        </div>
      )}
    </section>
  );
}