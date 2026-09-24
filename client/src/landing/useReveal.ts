import { RefObject, useEffect, useState } from "react";

/** Observa nodos con `data-reveal` dentro de un root y devuelve un getter de estado. */
export function useReveal(rootRef: RefObject<HTMLElement | null>) {
  const [revealed, setRevealed] = useState<Set<string>>(new Set());

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const id = entry.target.getAttribute("data-reveal") || "";
            setRevealed((prev) => new Set(prev).add(id));
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -48px 0px" },
    );

    root.querySelectorAll("[data-reveal]").forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, [rootRef]);

  const reveal = (id: string) => (revealed.has(id) ? "revealed" : "");
  return reveal;
}
