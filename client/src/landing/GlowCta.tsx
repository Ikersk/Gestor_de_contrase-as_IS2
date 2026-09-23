type GlowCtaProps = {
  children: React.ReactNode;
  onClick?: () => void;
  className?: string;
  type?: "button" | "submit";
};

/** CTA con borde 1px glow y hover expansivo. */
export function GlowCta({ children, onClick, className = "", type = "button" }: GlowCtaProps) {
  return (
    <button
      type={type}
      onClick={onClick}
      className={[
        "group relative inline-flex items-center gap-3",
        "px-7 py-3.5 rounded-full",
        "font-display text-[15px] font-semibold tracking-[0.02em]",
        "text-abyss bg-cyan-electric",
        "border border-cyan-400/60",
        "shadow-[0_0_0_1px_rgba(6,182,212,0.25),0_0_28px_rgba(6,182,212,0.35)]",
        "transition-all duration-300 ease-out",
        "hover:scale-[1.045] hover:bg-cyan-300",
        "hover:shadow-[0_0_0_1px_rgba(6,182,212,0.7),0_0_48px_rgba(6,182,212,0.65),0_0_80px_rgba(6,182,212,0.3)]",
        "focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-cyan-electric",
        "active:scale-[0.98]",
        className,
      ].join(" ")}
    >
      {children}
      <span
        aria-hidden="true"
        className="inline-block transition-transform duration-300 group-hover:translate-x-1 group-hover:-translate-y-0.5"
      >
        ↗
      </span>
    </button>
  );
}
