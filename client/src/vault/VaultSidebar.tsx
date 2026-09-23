import { useState, type ReactNode } from "react";

export type VaultFilter = "all" | "favorites" | "notes" | "cards";

interface VaultSidebarProps {
  filter: VaultFilter;
  onFilterChange: (filter: VaultFilter) => void;
  total: number;
  favorites: number;
  busy: boolean;
  onLogout: () => void;
  onOpenAccount: () => void;
}

const NAV: Array<{
  id: VaultFilter;
  label: string;
  mono: string;
  icon: ReactNode;
  live: boolean;
}> = [
  {
    id: "all",
    label: "Todos",
    mono: "ALL",
    live: true,
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </svg>
    ),
  },
  {
    id: "favorites",
    label: "Favoritos",
    mono: "FAV",
    live: true,
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
      </svg>
    ),
  },
  {
    id: "notes",
    label: "Notas Seguras",
    mono: "NOTE",
    live: false,
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <rect x="8" y="14" width="8" height="6" rx="1" />
        <path d="M10 14v-1a2 2 0 1 1 4 0v1" />
      </svg>
    ),
  },
  {
    id: "cards",
    label: "Tarjetas",
    mono: "CARD",
    live: false,
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="5" width="20" height="14" rx="2" />
        <line x1="2" y1="10" x2="22" y2="10" />
      </svg>
    ),
  },
];

export function VaultSidebar({
  filter,
  onFilterChange,
  total,
  favorites,
  busy,
  onLogout,
  onOpenAccount,
}: VaultSidebarProps) {
  const [purging, setPurging] = useState(false);

  function counts(id: VaultFilter) {
    if (id === "all") return total;
    if (id === "favorites") return favorites;
    return 0;
  }

  async function handleKillSwitch() {
    if (busy || purging) return;
    setPurging(true);
    await new Promise((r) => setTimeout(r, 350));
    try {
      await onLogout();
    } finally {
      setPurging(false);
    }
  }

  return (
    <aside
      className="flex h-full min-h-0 flex-col border-b border-line bg-vault-glass backdrop-blur-md lg:border-b-0 lg:border-r"
      aria-label="Navegación de la bóveda"
    >
      <div className="border-b border-line/60 px-4 py-3">
        <p className="font-mono text-[14px] uppercase tracking-[0.28em] text-ink-faint">
          // navigation
        </p>
      </div>

      <nav className="flex flex-1 min-h-0 flex-col gap-0.5 overflow-y-auto p-2">
        {NAV.map((item) => {
          const active = filter === item.id;
          const count = counts(item.id);
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onFilterChange(item.id)}
              aria-current={active ? "page" : undefined}
              className={`group flex w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-left transition-all duration-150 ${
                active
                  ? "border-cyan-500/50 bg-vault-accent-soft text-vault-accent shadow-[0_0_20px_rgba(6,182,212,0.12)]"
                  : "border-transparent text-ink-dim hover:border-cyan-500/40 hover:bg-vault-accent-softer hover:text-ink"
              }`}
            >
              <span
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md border transition-colors ${
                  active
                    ? "border-cyan-500/40 bg-vault-accent-softer text-vault-accent"
                    : "border-line bg-vault-soft-2 text-ink-faint group-hover:text-vault-accent"
                }`}
              >
                {item.icon}
              </span>
              <span className="flex min-w-0 flex-1 flex-col">
                <span className="truncate text-lg font-medium text-ink">{item.label}</span>
                <span className="font-mono text-[14px] uppercase tracking-[0.16em] text-ink-faint">
                  {item.mono}
                </span>
              </span>
              <span
                className={`font-mono text-[15px] tabular-nums ${
                  active ? "text-vault-accent" : "text-ink-faint"
                }`}
              >
                {item.live ? String(count).padStart(2, "0") : "—"}
              </span>
            </button>
          );
        })}
      </nav>

      <div className="border-t border-line/60 p-3 space-y-2">
        <button
          type="button"
          onClick={onOpenAccount}
          className="flex w-full items-center gap-2.5 rounded-lg border border-line bg-vault-soft-2 px-3 py-2.5 text-left text-lg text-ink-dim transition-all duration-150 hover:border-cyan-500/50 hover:bg-vault-accent-softer hover:text-ink"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
            <circle cx="12" cy="7" r="4" />
          </svg>
          <span className="flex-1">Mi Cuenta</span>
          <span className="font-mono text-[14px] text-ink-faint">CFG</span>
        </button>

        <button
          type="button"
          onClick={handleKillSwitch}
          disabled={busy || purging}
          className="group relative flex w-full items-center gap-2.5 overflow-hidden rounded-lg border border-fuchsia-500/50 bg-vault-fuchsia-soft px-3 py-3 text-left transition-all duration-150 hover:border-fuchsia-400/70 hover:bg-vault-fuchsia-soft hover:shadow-[0_0_24px_rgba(217,70,239,0.25)] disabled:opacity-60"
        >
          <span
            aria-hidden
            className="absolute inset-0 bg-[linear-gradient(135deg,transparent_0%,rgba(217,70,239,0.12)_50%,transparent_100%)] opacity-0 transition-opacity group-hover:opacity-100"
          />
          <svg
            width="15"
            height="15"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.75"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="relative text-vault-fuchsia group-hover:text-fuchsia-700 [data-theme=dark]:group-hover:text-fuchsia-300"
          >
            <path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
            <line x1="12" y1="2" x2="12" y2="12" />
          </svg>
          <span className="relative flex min-w-0 flex-1 flex-col">
            <span className="text-lg font-medium text-vault-fuchsia">
              {purging ? "Purgando..." : "Kill Switch"}
            </span>
            <span className="font-mono text-[14px] uppercase tracking-[0.16em] text-vault-fuchsia/85">
              {purging ? "WIPE_RAM" : "END_SESSION"}
            </span>
          </span>
          <span
            aria-hidden
            className={`relative h-2 w-2 rounded-full ${
              purging ? "bg-fuchsia-400 animate-pulse" : "bg-fuchsia-500/70"
            }`}
          />
        </button>
      </div>
    </aside>
  );
}
