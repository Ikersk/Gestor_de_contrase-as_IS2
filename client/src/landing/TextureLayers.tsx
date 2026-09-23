/** Capas fijas de textura: mesh gradients, dot-grid y grain overlay. */
export function TextureLayers() {
  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
      {/* Iluminación asimétrica: cian desde arriba-izq, púrpura desde abajo-der */}
      <div
        className="absolute -left-[28vw] -top-[30vh] h-[85vw] w-[85vw] rounded-full blur-[110px]"
        style={{ background: "radial-gradient(circle, var(--lp-mesh-a), transparent 62%)" }}
      />
      <div
        className="absolute -bottom-[35vh] -right-[25vw] h-[75vw] w-[75vw] rounded-full blur-[120px]"
        style={{ background: "radial-gradient(circle, var(--lp-mesh-b), transparent 62%)" }}
      />
      {/* Dot grid de terminal con máscara radial */}
      <div
        className="bg-dot-grid absolute inset-0"
        style={{
          opacity: "var(--lp-dot-opacity, 0.35)",
          maskImage: "radial-gradient(ellipse 90% 75% at 50% 18%, black 10%, transparent 72%)",
          WebkitMaskImage: "radial-gradient(ellipse 90% 75% at 50% 18%, black 10%, transparent 72%)",
        }}
      />
      {/* Grain granulado analógico */}
      <div
        className="bg-grain animate-grain absolute -inset-[4%] mix-blend-overlay"
        style={{ opacity: "var(--lp-grain-opacity)" }}
      />
    </div>
  );
}
