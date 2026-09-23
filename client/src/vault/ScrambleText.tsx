import { useEffect, useState } from "react";

const GLYPHS = "ABCDEF0123456789#$%&*<>/\\";

function prefersReducedMotion() {
  return typeof window !== "undefined"
    && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

interface ScrambleTextProps {
  value: string;
  /** Cambiar este valor reinicia la animación de descifrado. */
  trigger: string | number;
  className?: string;
  durationMs?: number;
}

/** Simula un descifrado AES-GCM: glifos aleatorios que se congelan de izquierda a derecha. */
export function ScrambleText({
  value,
  trigger,
  className,
  durationMs = 420,
}: ScrambleTextProps) {
  const [display, setDisplay] = useState(value);

  useEffect(() => {
    if (prefersReducedMotion()) {
      setDisplay(value);
      return;
    }
    if (!value) {
      setDisplay("");
      return;
    }

    const steps = Math.min(14, Math.max(8, Math.ceil(value.length / 2)));
    const interval = Math.max(28, Math.floor(durationMs / steps));
    let frame = 0;
    setDisplay(
      Array.from({ length: value.length }, () =>
        GLYPHS[Math.floor(Math.random() * GLYPHS.length)],
      ).join(""),
    );

    const id = window.setInterval(() => {
      frame += 1;
      const progress = frame / steps;
      const locked = Math.floor(progress * value.length);
      let out = value.slice(0, locked);
      for (let i = locked; i < value.length; i += 1) {
        out += GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
      }
      setDisplay(out);
      if (frame >= steps) {
        setDisplay(value);
        window.clearInterval(id);
      }
    }, interval);

    return () => window.clearInterval(id);
  }, [value, trigger, durationMs]);

  return <span className={className}>{display}</span>;
}
