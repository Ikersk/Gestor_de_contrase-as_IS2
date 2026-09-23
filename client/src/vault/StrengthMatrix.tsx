export type StrengthLevel = 0 | 1 | 2 | 3 | 4;

export function estimateEntropy(password: string): number {
  const alphabetSize = new Set(password).size;
  return password.length * Math.log2(alphabetSize || 1);
}

export function strengthLevel(password: string, breached = false): StrengthLevel {
  if (!password) return 0;
  const entropy = estimateEntropy(password);
  if (breached || password.length < 10 || entropy < 40) return 1;
  if (entropy < 60) return 2;
  if (entropy < 80) return 3;
  return 4;
}

const LEVEL_COLORS: Record<StrengthLevel, string> = {
  0: "bg-vault-track",
  1: "bg-red-500 [data-theme=dark]:bg-red-400",
  2: "bg-amber-500 shadow-[0_0_6px_rgba(245,158,11,0.6)] [data-theme=dark]:bg-amber-400",
  3: "bg-cyan-600 shadow-[0_0_6px_rgba(6,182,212,0.7)] [data-theme=dark]:bg-cyan-400",
  4: "bg-lime-600 shadow-[0_0_6px_rgba(101,163,13,0.7)] [data-theme=dark]:bg-lime-300",
};

const LEVEL_LABELS: Record<StrengthLevel, string> = {
  0: "Vacía",
  1: "Débil",
  2: "Media",
  3: "Fuerte",
  4: "Excelente",
};

const DOTS = 8;

interface StrengthMatrixProps {
  password: string;
  breached?: boolean;
  className?: string;
  showLabel?: boolean;
}

/** Matriz de puntos que refleja la fuerza de la contraseña (estética terminal). */
export function StrengthMatrix({
  password,
  breached = false,
  className = "",
  showLabel = false,
}: StrengthMatrixProps) {
  const level = strengthLevel(password, breached);
  const filled = level === 0 ? 0 : Math.max(2, Math.round((level / 4) * DOTS));
  const color = LEVEL_COLORS[level];

  return (
    <div
      className={`flex items-center gap-2 ${className}`}
      title={`Fuerza: ${LEVEL_LABELS[level]}`}
      aria-label={`Fuerza de la contraseña: ${LEVEL_LABELS[level]}`}
    >
      <div className="flex items-center gap-[3px]" aria-hidden>
        {Array.from({ length: DOTS }, (_, i) => (
          <span
            key={i}
            className={`h-1.5 w-1.5 rounded-full transition-colors duration-200 ${
              i < filled ? color : "bg-vault-track"
            }`}
          />
        ))}
      </div>
      {showLabel && (
        <span className="font-mono text-[14px] uppercase tracking-[0.14em] text-ink-faint">
          {LEVEL_LABELS[level]}
        </span>
      )}
    </div>
  );
}
