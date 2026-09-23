import type { ReactNode } from "react";
import { useState } from "react";
import type { DecryptedCredential } from "../vault";
import type { VaultHealthReport } from "../vault-health";
import { ThemeSwitcher } from "../ThemeSwitcher";
import { TextureLayers } from "../landing/TextureLayers";
import { CredentialDetailPanel } from "./CredentialDetailPanel";
import { CredentialList } from "./CredentialList";
import { VaultSidebar, type VaultFilter } from "./VaultSidebar";

function VaultSkeleton() {
  return (
    <div className="flex h-full min-h-0 flex-col gap-4 p-6" aria-hidden="true">
      <div className="h-2 w-full animate-pulse rounded bg-vault-track" />
      <div className="grid grid-cols-4 gap-3">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="h-16 animate-pulse rounded-xl border border-line bg-vault-soft" />
        ))}
      </div>
      <div className="grid flex-1 min-h-0 gap-4 lg:grid-cols-[240px_1fr_380px]">
        <div className="space-y-2">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="h-12 animate-pulse rounded-lg bg-vault-soft" />
          ))}
        </div>
        <div className="space-y-3">
          {[0, 1, 2, 3, 4].map((i) => (
            <div key={i} className="h-20 animate-pulse rounded-xl bg-vault-soft" />
          ))}
        </div>
        <div className="h-64 animate-pulse rounded-xl bg-vault-soft" />
      </div>
    </div>
  );
}

export interface VaultShellProps {
  decrypting: boolean;
  credentials: DecryptedCredential[];
  selectedCredentialId: number | string | null;
  healthReport: VaultHealthReport;
  affectedIds: Set<number | string>;
  breachedIds: Set<number | string>;
  breachError: string | null;
  isCheckingBreach: boolean;
  busy: boolean;
  onSelectCredential: (id: number | string) => void;
  onToggleFavorite: (id: number | string) => void;
  onCheckBreach: () => void;
  onLogout: () => void;
  onOpenAccount: () => void;
  onOpenNew: () => void;
  onOpenEdit: (id: number | string) => void;
  onRequestDelete: (id: number | string) => void;
  /** Modales, feedback y toasts de la app. */
  children?: ReactNode;
}

/** Shell visual de la bóveda: 3 columnas, texturas landing y glass militar. */
export function VaultShell({
  decrypting,
  credentials,
  selectedCredentialId,
  healthReport,
  affectedIds,
  breachedIds,
  breachError,
  isCheckingBreach,
  busy,
  onSelectCredential,
  onToggleFavorite,
  onCheckBreach,
  onLogout,
  onOpenAccount,
  onOpenNew,
  onOpenEdit,
  onRequestDelete,
  children,
}: VaultShellProps) {
  const [filter, setFilter] = useState<VaultFilter>("all");
  const favorites = credentials.filter((c) => c.favorite).length;
  const selected =
    credentials.find((c) => c.id === selectedCredentialId) ?? null;

  return (
    <main
      className="landing-page relative flex h-screen min-h-[560px] flex-col overflow-hidden bg-vault-page font-sans text-lg text-ink"
      style={{ "--lp-mesh-b": "transparent" } as React.CSSProperties}
    >
      <TextureLayers />

      {/* Marca de agua de fondo (solo se ve en el fondo, paneles opacos la tapan) */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-x-0 bottom-0 z-0 flex justify-center overflow-hidden"
      >
        <span className="translate-y-[28%] select-none font-display text-[42vw] font-bold leading-none tracking-tighter text-ink opacity-[var(--lp-watermark-opacity)]">
          ARCA
        </span>
      </div>

      <header className="relative z-10 flex shrink-0 items-center justify-between border-b border-line bg-vault-glass-strong px-4 py-3 backdrop-blur-md lg:px-5">
        <div className="flex items-center gap-4">
          <a className="brand group flex items-center gap-2" href="/" aria-label="Arca, inicio">
            <span className="brand-symbol">A</span>
            <span className="font-display text-2xl font-semibold tracking-tight text-ink">
              arca
            </span>
          </a>
          <span
            aria-hidden
            className="hidden font-mono text-[14px] uppercase tracking-[0.28em] text-ink-faint sm:inline"
          >
            // boveda
          </span>
          <span className="live-indicator ml-1 hidden sm:inline-flex" aria-hidden />
        </div>
        <div className="flex items-center gap-3">
          <span className="hidden font-mono text-[14px] uppercase tracking-[0.16em] text-ink-faint md:inline">
          </span>
          <ThemeSwitcher />
        </div>
      </header>

      {decrypting ? (
        <div className="relative z-10 min-h-0 flex-1">
          <VaultSkeleton />
        </div>
      ) : (
        <div className="relative z-10 grid min-h-0 flex-1 grid-cols-1 grid-rows-[auto_minmax(0,1fr)] overflow-hidden lg:grid-cols-[240px_minmax(0,1fr)_minmax(300px,400px)] lg:grid-rows-1 xl:grid-cols-[248px_minmax(0,1fr)_minmax(340px,420px)]">
          <div className="min-h-0 lg:row-span-1 lg:h-full max-lg:max-h-[220px]">
            <VaultSidebar
              filter={filter}
              onFilterChange={setFilter}
              total={credentials.length}
              favorites={favorites}
              busy={busy}
              onLogout={onLogout}
              onOpenAccount={onOpenAccount}
            />
          </div>

          <div className="flex min-h-0 min-w-0 flex-col lg:h-full max-lg:max-h-[55vh]">
            <CredentialList
              credentials={credentials}
              filter={filter}
              selectedId={selectedCredentialId}
              affectedIds={affectedIds}
              breachedIds={breachedIds}
              healthReport={healthReport}
              breachError={breachError}
              isCheckingBreach={isCheckingBreach}
              onCheckBreach={onCheckBreach}
              onSelect={onSelectCredential}
              onToggleFavorite={onToggleFavorite}
              onAddNew={onOpenNew}
            />
          </div>

          <div className="min-h-0 border-line bg-vault-glass backdrop-blur-md lg:h-full lg:border-l max-lg:min-h-[40vh] max-lg:border-t">
            <CredentialDetailPanel
              key={selected?.id ?? "empty"}
              credential={selected}
              onEdit={onOpenEdit}
              onDelete={onRequestDelete}
              breachedIds={breachedIds}
              busy={busy}
            />
          </div>
        </div>
      )}

      {children}

      {/* Dot grid visible sobre paneles sólidos de la bóveda */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 z-[60] bg-dot-grid-overlay"
        style={{ opacity: "var(--lp-dot-overlay-opacity, 0.55)" }}
      />
    </main>
  );
}
