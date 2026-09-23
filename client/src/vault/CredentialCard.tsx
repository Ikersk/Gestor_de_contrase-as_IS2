import type { DecryptedCredential } from "../vault";
import { StrengthMatrix } from "./StrengthMatrix";

export function getFaviconUrl(url: string): string | null {
  try {
    const { hostname } = new URL(url);
    if (!hostname) return null;
    return `https://www.google.com/s2/favicons?domain=${hostname}&sz=64`;
  } catch {
    return null;
  }
}

interface CredentialCardProps {
  credential: DecryptedCredential;
  selected: boolean;
  affected: boolean;
  breached: boolean;
  onSelect: (id: number | string) => void;
  onToggleFavorite: (id: number | string) => void;
}

export function CredentialCard({
  credential,
  selected,
  affected,
  breached,
  onSelect,
  onToggleFavorite,
}: CredentialCardProps) {
  const firstUrl = credential.urls.find((u) => u.length > 0);
  const faviconUrl = firstUrl ? getFaviconUrl(firstUrl) : null;
  const hasTotp = Boolean(credential.totpSecret);
  const favorite = Boolean(credential.favorite);

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(credential.id)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(credential.id);
        }
      }}
      className={`group relative flex w-full cursor-pointer items-center gap-3 overflow-hidden rounded-xl border p-3 text-left backdrop-blur-md transition-all duration-200 ${
        selected
          ? "border-cyan-500/60 bg-vault-accent-soft shadow-[0_0_36px_rgba(6,182,212,0.18)]"
          : "border-line bg-vault-glass hover:-translate-y-0.5 hover:border-cyan-500/50 hover:bg-vault-accent-softer hover:shadow-[0_0_36px_rgba(6,182,212,0.15)]"
      }`}
    >
      {selected && (
        <span
          aria-hidden
          className="absolute inset-y-0 left-0 w-0.5 bg-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.9)]"
        />
      )}

      <div className="relative flex h-10 w-10 shrink-0 items-center justify-center overflow-hidden rounded-lg border border-line bg-vault-soft-2">
        {faviconUrl ? (
          <img
            src={faviconUrl}
            alt=""
            width={22}
            height={22}
            className="h-[22px] w-[22px]"
            onError={(e) => {
              (e.currentTarget as HTMLImageElement).style.display = "none";
            }}
          />
        ) : null}
        <span
          className={`absolute inset-0 flex items-center justify-center font-display text-lg font-semibold text-vault-accent ${
            faviconUrl ? "opacity-0" : "opacity-100"
          }`}
        >
          {credential.title.charAt(0).toUpperCase()}
        </span>
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-lg font-medium text-ink">
            {credential.title}
          </span>
          {hasTotp && (
            <span className="rounded border border-cyan-500/50 bg-vault-accent-soft px-1 py-px font-mono text-[13px] uppercase tracking-[0.12em] text-vault-accent">
              2FA
            </span>
          )}
          {breached ? (
            <span className="rounded border border-rose-500/50 bg-vault-danger-soft px-1 py-px font-mono text-[13px] font-bold text-vault-danger">
              !
            </span>
          ) : affected ? (
            <span className="rounded border border-amber-500/50 bg-vault-warn-soft px-1 py-px font-mono text-[13px] font-bold text-vault-warn">
              !
            </span>
          ) : null}
        </div>
        <div className="mt-1 flex items-center gap-2">
          <span className="truncate font-mono text-[15px] text-ink-faint">
            {credential.username}
          </span>
        </div>
        <StrengthMatrix
          password={credential.password}
          breached={breached}
          className="mt-1.5"
        />
      </div>

      <button
        type="button"
        aria-label={favorite ? "Quitar de favoritos" : "Añadir a favoritos"}
        title={favorite ? "Quitar de favoritos" : "Añadir a favoritos"}
        onClick={(e) => {
          e.stopPropagation();
          onToggleFavorite(credential.id);
        }}
        className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md border transition-all duration-150 ${
          favorite
            ? "border-amber-500/50 bg-vault-warn-soft text-amber-700 shadow-[0_0_12px_rgba(251,191,36,0.25)] [data-theme=dark]:text-amber-300"
            : "border-transparent text-ink-faint opacity-0 hover:border-amber-500/50 hover:bg-vault-warn-soft hover:text-amber-700 [data-theme=dark]:hover:text-amber-300 focus:opacity-100 group-hover:opacity-100"
        }`}
      >
        <svg
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill={favorite ? "currentColor" : "none"}
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
        </svg>
      </button>
    </div>
  );
}
