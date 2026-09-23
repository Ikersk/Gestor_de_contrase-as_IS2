import { useMemo, useState } from "react";
import type { DecryptedCredential } from "../vault";
import type { VaultHealthReport } from "../vault-health";
import { CredentialCard } from "./CredentialCard";
import type { VaultFilter } from "./VaultSidebar";

interface MetricStripProps {
  credentials: DecryptedCredential[];
  healthReport: VaultHealthReport;
  breachedCount: number;
  breachError: string | null;
  isCheckingBreach: boolean;
  onCheckBreach: () => void;
}

function MetricStrip({
  credentials,
  healthReport,
  breachedCount,
  breachError,
  isCheckingBreach,
  onCheckBreach,
}: MetricStripProps) {
  const weakCount = healthReport.weak.length;
  const reusedCount = healthReport.reused.length;
  const totalAlerts = weakCount + reusedCount + breachedCount;

  const metrics = [
    {
      key: "health",
      label: "SALUD",
      value: `${healthReport.score}%`,
      accent: healthReport.score >= 80 ? "text-vault-ok" : healthReport.score >= 50 ? "text-vault-warn" : "text-vault-danger",
      bar: healthReport.score / 100,
    },
    {
      key: "total",
      label: "ITEMS",
      value: String(credentials.length).padStart(2, "0"),
      accent: "text-vault-accent",
      bar: null,
    },
    {
      key: "alerts",
      label: "ALERTAS",
      value: String(totalAlerts).padStart(2, "0"),
      accent: totalAlerts > 0 ? "text-vault-warn" : "text-ink-dim",
      bar: null,
      detail: totalAlerts > 0 ? `${weakCount}D · ${reusedCount}R` : null,
    },
    {
      key: "breach",
      label: "HIBP",
      value: String(breachedCount).padStart(2, "0"),
      accent: breachedCount > 0 ? "text-vault-danger" : "text-ink-dim",
      bar: null,
      detail: breachedCount > 0 ? "CRÍTICO" : null,
    },
  ];

  return (
    <div className="border-b border-line/60 px-4 py-3">
      <div className="flex items-center justify-between gap-2 mb-2">
        <p className="font-mono text-[14px] uppercase tracking-[0.28em] text-ink-faint">
          // vault_status
        </p>
        <button
          type="button"
          onClick={onCheckBreach}
          disabled={isCheckingBreach || credentials.length === 0}
          className="rounded border border-line bg-vault-soft-2 px-2 py-1 font-mono text-[14px] uppercase tracking-[0.12em] text-ink-dim transition-colors hover:border-cyan-500/50 hover:text-vault-accent disabled:opacity-40"
        >
          {isCheckingBreach ? "SCAN..." : "SCAN HIBP"}
        </button>
      </div>
      <div className="grid grid-cols-4 gap-2">
        {metrics.map((m) => (
          <div
            key={m.key}
            className="rounded-lg border border-line bg-vault-glass px-2.5 py-2 backdrop-blur-sm transition-colors hover:border-cyan-500/40"
          >
            <p className="font-mono text-[13px] uppercase tracking-[0.18em] text-ink-faint">
              {m.label}
            </p>
            <p className={`font-mono text-2xl font-semibold tabular-nums leading-tight ${m.accent}`}>
              {m.value}
            </p>
            {typeof m.bar === "number" && (
              <div className="mt-1 h-0.5 overflow-hidden rounded-full bg-vault-track">
                <span
                  className="block h-full origin-left bg-cyan-600 [data-theme=dark]:bg-cyan-400 transition-transform duration-500"
                  style={{ transform: `scaleX(${m.bar})`, width: "100%" }}
                />
              </div>
            )}
            {m.detail && (
              <p className="mt-0.5 font-mono text-[13px] tracking-wide text-ink-faint">
                {m.detail}
              </p>
            )}
          </div>
        ))}
      </div>
      {breachError && (
        <p className="mt-2 font-mono text-[15px] text-vault-fuchsia" role="alert">
          {breachError}
        </p>
      )}
    </div>
  );
}

interface CredentialListProps {
  credentials: DecryptedCredential[];
  filter: VaultFilter;
  selectedId: number | string | null;
  affectedIds: Set<number | string>;
  breachedIds: Set<number | string>;
  healthReport: VaultHealthReport;
  breachError: string | null;
  isCheckingBreach: boolean;
  onCheckBreach: () => void;
  onSelect: (id: number | string) => void;
  onToggleFavorite: (id: number | string) => void;
  onAddNew: () => void;
}

export function CredentialList({
  credentials,
  filter,
  selectedId,
  affectedIds,
  breachedIds,
  healthReport,
  breachError,
  isCheckingBreach,
  onCheckBreach,
  onSelect,
  onToggleFavorite,
  onAddNew,
}: CredentialListProps) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    let items = credentials;
    if (filter === "favorites") {
      items = items.filter((c) => c.favorite);
    }
    const q = query.trim().toLowerCase();
    if (q) {
      items = items.filter(
        (c) =>
          c.title.toLowerCase().includes(q) ||
          c.username.toLowerCase().includes(q),
      );
    }
    return items;
  }, [credentials, filter, query]);

  const isModuleFilter = filter === "notes" || filter === "cards";

  return (
    <section
      className="flex h-full min-h-0 flex-col border-b border-line bg-vault-panel lg:border-b-0 lg:border-r"
      aria-label="Lista de credenciales"
    >
      <MetricStrip
        credentials={credentials}
        healthReport={healthReport}
        breachedCount={breachedIds.size}
        breachError={breachError}
        isCheckingBreach={isCheckingBreach}
        onCheckBreach={onCheckBreach}
      />

      <div className="flex items-center gap-2 border-b border-line/60 px-4 py-3">
        <div className="relative flex-1">
          <svg
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint"
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Buscar accesos..."
            aria-label="Buscar credenciales"
            disabled={isModuleFilter}
            className="w-full rounded-lg border border-line bg-vault-input py-2 pl-9 pr-3 font-mono text-base text-ink placeholder:text-ink-faint outline-none transition focus:border-cyan-500/60 focus:shadow-[0_0_0_3px_rgba(6,182,212,0.15)] disabled:opacity-40"
          />
        </div>
        <button
          type="button"
          onClick={onAddNew}
          className="shrink-0 rounded-lg border border-cyan-500/50 bg-vault-accent-soft px-3 py-2 font-mono text-[15px] uppercase tracking-[0.1em] text-vault-accent transition-all duration-150 hover:border-cyan-400 hover:bg-cyan-500/30 hover:shadow-[0_0_18px_rgba(6,182,212,0.3)]"
        >
          + Nuevo
        </button>
      </div>

      <div className="min-h-0 flex-1 space-y-2 overflow-y-auto p-3">
        {isModuleFilter ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-line bg-vault-glass p-6 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-line bg-vault-soft-2 text-ink-faint">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <p className="font-mono text-[15px] uppercase tracking-[0.18em] text-vault-accent">
              MODULE_LOCKED
            </p>
            <p className="max-w-[22ch] text-lg text-ink-dim">
              {filter === "notes"
                ? "Notas Seguras: módulo cifrado — próximamente."
                : "Tarjetas: módulo cifrado — próximamente."}
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-line bg-vault-glass p-6 text-center">
            <span className="font-mono text-4xl text-vault-accent">+</span>
            <p className="max-w-[28ch] text-lg text-ink-dim">
              {credentials.length === 0
                ? "Añade tu primer acceso para tenerlo disponible cuando lo necesites."
                : filter === "favorites"
                  ? "Sin favoritos. Marca una estrella en cualquier credencial."
                  : "Sin resultados para esa búsqueda."}
            </p>
            {credentials.length === 0 && (
              <button
                type="button"
                onClick={onAddNew}
                className="mt-1 rounded-lg border border-cyan-500/50 bg-vault-accent-soft px-3 py-1.5 font-mono text-[15px] uppercase tracking-wider text-vault-accent hover:bg-cyan-500/30"
              >
                + Nuevo acceso
              </button>
            )}
          </div>
        ) : (
          filtered.map((item) => (
            <CredentialCard
              key={item.id}
              credential={item}
              selected={selectedId === item.id}
              affected={affectedIds.has(item.id)}
              breached={breachedIds.has(item.id)}
              onSelect={onSelect}
              onToggleFavorite={onToggleFavorite}
            />
          ))
        )}
      </div>
    </section>
  );
}
