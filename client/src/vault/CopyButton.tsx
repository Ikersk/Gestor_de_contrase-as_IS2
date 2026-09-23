import { useEffect, useRef, useState } from "react";

interface CopyButtonProps {
  value: string;
  label?: string;
  className?: string;
  title?: string;
}

async function writeClipboard(text: string): Promise<boolean> {
  if (!navigator.clipboard) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Botón de copia con destello cyan y swap a check (feedback técnico). */
export function CopyButton({
  value,
  label = "Copiar",
  className = "",
  title,
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) window.clearTimeout(timerRef.current);
    };
  }, []);

  async function handleClick() {
    const ok = await writeClipboard(value);
    setCopied(ok);
    setFailed(!ok);
    if (timerRef.current) window.clearTimeout(timerRef.current);
    timerRef.current = window.setTimeout(() => {
      setCopied(false);
      setFailed(false);
    }, 1600);
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      title={title ?? (copied ? "Copiado" : failed ? "Error al copiar" : label)}
      aria-label={title ?? label}
      className={`group relative inline-flex shrink-0 items-center justify-center gap-1.5 overflow-hidden rounded-md border px-2.5 py-1.5 font-mono text-[15px] uppercase tracking-[0.12em] transition-all duration-150 ${
        copied
          ? "border-cyan-500/60 bg-vault-accent-soft text-vault-accent shadow-[0_0_16px_rgba(6,182,212,0.25)]"
          : failed
            ? "border-red-500/50 bg-vault-danger-soft text-vault-danger"
            : "border-line bg-vault-soft-2 text-ink-dim hover:border-cyan-500/50 hover:bg-vault-accent-softer hover:text-vault-accent"
      } ${className}`}
    >
      {copied && (
        <span
          aria-hidden
          className="pointer-events-none absolute inset-0 animate-ping bg-cyan-400/20"
        />
      )}
      <span className="relative z-10 flex items-center gap-1.5">
        {copied ? (
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M20 6 9 17l-5-5" />
          </svg>
        ) : (
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
        )}
        {copied ? "Copiado" : failed ? "Error" : label}
      </span>
    </button>
  );
}
