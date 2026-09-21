import type { DecryptedCredential } from "./vault";
import type { VaultHealthReport } from "./vault-health";

interface SecurityDashboardProps {
  credentials: DecryptedCredential[];
  healthReport: VaultHealthReport;
  breachedCount: number;
  breachError: string | null;
}

export function SecurityDashboard({
  credentials,
  healthReport,
  breachedCount,
  breachError,
}: SecurityDashboardProps) {
  const weakCount = healthReport.weak.length;
  const reusedCount = healthReport.reused.length;
  const totalAlerts = weakCount + reusedCount + breachedCount;

  return (
    <section className="security-dashboard" aria-label="Panel de seguridad">
      <div className="dashboard-metrics">
        <div className="metric-card metric-card--health">
          <div className="metric-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
          </div>
          <div className="metric-content">
            <span className="metric-value">{healthReport.score}%</span>
            <span className="metric-label">Salud</span>
          </div>
          <div
            className="metric-progress"
            role="progressbar"
            aria-label="Salud de la bóveda"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={healthReport.score}
          >
            <span style={{ transform: `scaleX(${healthReport.score / 100})` }} />
          </div>
        </div>

        <div className="metric-card metric-card--total">
          <div className="metric-icon metric-icon--blue">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>
          <div className="metric-content">
            <span className="metric-value">{credentials.length}</span>
            <span className="metric-label">Credenciales</span>
          </div>
        </div>

        <div className={`metric-card metric-card--alerts ${totalAlerts > 0 ? "metric-card--warning" : ""}`}>
          <div className="metric-icon metric-icon--amber">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <div className="metric-content">
            <span className="metric-value">{totalAlerts}</span>
            <span className="metric-label">Alertas</span>
          </div>
          {totalAlerts > 0 && (
            <div className="metric-breakdown">
              {weakCount > 0 && <span className="metric-badge metric-badge--weak">{weakCount} débiles</span>}
              {reusedCount > 0 && <span className="metric-badge metric-badge--reused">{reusedCount} reutilizadas</span>}
            </div>
          )}
        </div>

        <div className={`metric-card metric-card--breach ${breachedCount > 0 ? "metric-card--danger" : ""}`}>
          <div className="metric-icon metric-icon--red">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <div className="metric-content">
            <span className="metric-value">{breachedCount}</span>
            <span className="metric-label">Brechas HIBP</span>
          </div>
          {breachedCount > 0 && (
            <span className="metric-badge metric-badge--critical">Crítico</span>
          )}
        </div>
      </div>

      {breachError && <p className="breach-error">{breachError}</p>}
    </section>
  );
}
