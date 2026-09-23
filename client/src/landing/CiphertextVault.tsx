import { useCallback, useEffect, useState } from "react";

type CipherState = { iv: string; ciphertext: string } | null;

/** Demo en vivo de AES-GCM: cifra el input con Web Crypto y muestra ciphertext/IV. */
function CryptoDemo() {
  const [input, setInput] = useState("");
  const [cipher, setCipher] = useState<CipherState>(null);
  const [encrypting, setEncrypting] = useState(false);

  const encrypt = useCallback(async (plain: string) => {
    if (!plain) {
      setCipher(null);
      return;
    }
    setEncrypting(true);
    try {
      const enc = new TextEncoder();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"]);
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plain));
      setCipher({
        iv: Array.from(iv).map((b) => b.toString(16).padStart(2, "0")).join(""),
        ciphertext:
          Array.from(new Uint8Array(ct))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("")
            .slice(0, 96) + "…",
      });
    } catch {
      setCipher(null);
    } finally {
      setEncrypting(false);
    }
  }, []);

  useEffect(() => {
    const t = setTimeout(() => encrypt(input), 300);
    return () => clearTimeout(t);
  }, [input, encrypt]);

  return (
    <div className="space-y-4">
      <label
        className="block font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-cyan-electric"
        htmlFor="demo-input"
      >
        Plaintext → AES-256-GCM
      </label>
      <input
        id="demo-input"
        type="text"
        placeholder="Escribe un secreto para cifrar…"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        autoComplete="off"
        spellCheck={false}
        className="w-full rounded-lg border border-line bg-black/40 px-3.5 py-3 font-mono text-sm text-ink placeholder:text-ink-faint/70 outline-none transition focus:border-cyan-electric/70 focus:shadow-[0_0_0_3px_rgba(6,182,212,0.18)] [data-theme=light]_&:bg-white/25"
      />
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-lg border border-line bg-abyss/70 p-3">
          <span className="mb-1.5 block font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-cyan-electric">
            Ciphertext
          </span>
          <code className="block break-all font-mono text-[11px] leading-relaxed text-ink-dim">
            {cipher ? cipher.ciphertext : "af09c1b3e7…"}
          </code>
        </div>
        <div className="rounded-lg border border-line bg-abyss/70 p-3">
          <span className="mb-1.5 block font-mono text-[9px] font-bold uppercase tracking-[0.16em] text-acid">
            IV · 12 bytes
          </span>
          <code className="block break-all font-mono text-[11px] leading-relaxed text-acid">
            {cipher ? cipher.iv : "a4f208e19c3b…"}
          </code>
        </div>
      </div>
      <p className="font-mono text-[10px] leading-relaxed text-ink-faint">
        {encrypting
          ? "› cifrando con AES-256-GCM…"
          : cipher
            ? "› generado localmente · Web Crypto API · el servidor jamás ve este dato"
            : "› escribe para ver cómo se cifra en tu navegador"}
      </p>
    </div>
  );
}

/**
 * Caja fuerte digital: bloque de ciphertext flotante con cerradura
 * e integración del CryptoDemo en vivo.
 */
export function CiphertextVault() {
  return (
    <div className="relative w-full max-w-[540px] animate-float">
      {/* Halo detrás de la tarjeta */}
      <div
        aria-hidden="true"
        className="absolute -inset-6 rounded-[28px] opacity-70 blur-2xl"
        style={{
          background:
            "radial-gradient(ellipse at 30% 20%, var(--lp-mesh-a), transparent 55%), radial-gradient(ellipse at 80% 80%, var(--lp-mesh-b), transparent 55%)",
        }}
      />

      <div className="relative overflow-hidden rounded-2xl border border-line-strong bg-surface backdrop-blur-xl shadow-[0_24px_80px_rgba(0,0,0,0.45)]">
        {/* Barra superior estilo hardware de seguridad */}
        <div className="flex items-center gap-2 border-b border-line bg-surface-2 px-4 py-3">
          <span className="h-2.5 w-2.5 rounded-full bg-[#ff5f57]" />
          <span className="h-2.5 w-2.5 rounded-full bg-[#febc2e]" />
          <span className="h-2.5 w-2.5 rounded-full bg-[#28c840]" />
          <span className="ml-2 font-mono text-[10px] tracking-wider text-ink-faint">
            arca://vault-core
          </span>
          <span className="ml-auto flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-[0.14em] text-acid">
            <span className="animate-pulse-glow h-1.5 w-1.5 rounded-full bg-acid" />
            sealed
          </span>
        </div>

        {/* Glifo de cerradura + hex flotante */}
        <div className="relative border-b border-line px-6 py-7">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 opacity-[0.07]"
            style={{
              backgroundImage:
                "linear-gradient(90deg, currentColor 1px, transparent 1px), linear-gradient(currentColor 1px, transparent 1px)",
              backgroundSize: "24px 24px",
              color: "var(--lp-ink)",
            }}
          />
          <div className="relative flex items-center gap-5">
            <div className="relative grid h-16 w-16 shrink-0 place-items-center rounded-xl border border-cyan-electric/40 bg-cyan-electric/10 shadow-[0_0_24px_rgba(6,182,212,0.25)]">
              <svg
                width="28"
                height="28"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="text-cyan-electric"
                aria-hidden="true"
              >
                <rect x="3" y="11" width="18" height="11" rx="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                <circle cx="12" cy="16" r="1" />
              </svg>
            </div>
            <div className="min-w-0">
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-ink-faint">
                digital safe · split-key
              </p>
              <p className="mt-1 font-mono text-sm leading-relaxed text-ink-dim">
                <span className="text-cyan-electric">c7f3</span>
                <span className="text-ink-faint">a91e0b</span>
                <span className="text-acid">4d2c</span>
                <span className="text-ink-faint">ee19…</span>
                <br />
                <span className="text-ink-faint">bloque ilegible · solo tu RAM lo abre</span>
              </p>
            </div>
          </div>
        </div>

        {/* Demo interactivo integrado */}
        <div className="px-6 py-6">
          <CryptoDemo />
        </div>
      </div>
    </div>
  );
}
