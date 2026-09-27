import React, { useEffect, useRef, useState, useCallback } from 'react';

/**
 * CaptchaBox — SHA-256 Proof of Work CAPTCHA
 *
 * ¿Por qué SHA-256 y no MurmurHash3?
 * ─────────────────────────────────────────────────────────────────────────
 * MurmurHash3 es un hash NO CRIPTOGRÁFICO diseñado para velocidad y buena
 * distribución estadística (tablas hash, bases de datos). NO ofrece ninguna
 * garantía de resistencia a preimagen, colisión deliberada o ataques de
 * longitud de extensión.
 *
 * SHA-256 (Secure Hash Algorithm 256-bit), en cambio:
 *   1. Resistencia a preimagen: dado H, es computacionalmente imposible
 *      encontrar M tal que SHA-256(M) = H.
 *   2. Resistencia a segunda preimagen: dado M₁, es imposible encontrar
 *      M₂ ≠ M₁ con el mismo hash.
 *   3. Resistencia a colisión: es imposible encontrar dos mensajes distintos
 *      con el mismo hash.
 *   4. Es el estándar NIST FIPS 180-4, auditado por la comunidad criptográfica
 *      global durante más de 25 años sin ataques prácticos conocidos.
 *   5. Está disponible NATIVAMENTE en todos los navegadores modernos via
 *      SubtleCrypto API — sin dependencias externas.
 *
 * ¿Por qué SHA-256 es coherente con ARCA?
 * ─────────────────────────────────────────────────────────────────────────
 * El resto del sistema (KDF, cifrado de la bóveda, autenticación) ya usa
 * SHA-256 y derivados (PBKDF2-SHA-256, HKDF-SHA-256, AES-256-GCM).
 * Usar SHA-256 en el PoW mantiene la homogeneidad criptográfica del sistema.
 *
 * ¿Cómo funciona el PoW con SHA-256?
 * ─────────────────────────────────────────────────────────────────────────
 * El cliente debe encontrar un nonce N tal que:
 *   SHA-256(desafío + ":" + N) tenga los primeros DIFFICULTY bits en cero.
 *
 * Dificultad 18 bits → 2¹⁸ = 262,144 intentos promedio
 * SHA-256 en Worker: ~200,000-400,000 hashes/seg
 * Tiempo esperado: 0.6 - 1.5 segundos
 *
 * Un bot PUEDE resolverlo pero debe gastar ese tiempo por cada intento,
 * limitando ataques de fuerza bruta a ~40-100 intentos/minuto.
 */

interface CaptchaBoxProps {
  onVerifyChange: (isVerified: boolean) => void;
  className?: string;
}

// ─── Web Worker (inline via Blob) — sin archivo externo ──────────────────────
// SubtleCrypto está disponible en Workers: self.crypto.subtle
const WORKER_CODE = `
const ENCODER = new TextEncoder();

/**
 * Verifica si los primeros 'zeroBits' del buffer SHA-256 son cero.
 * Equivalente a comparar el hash con un target de dificultad Bitcoin-style.
 */
function meetsTarget(hashBuffer, zeroBits) {
  const view = new Uint8Array(hashBuffer);
  const fullBytes = Math.floor(zeroBits / 8);
  const remainingBits = zeroBits % 8;

  for (let i = 0; i < fullBytes; i++) {
    if (view[i] !== 0) return false;
  }
  if (remainingBits > 0) {
    const mask = (0xFF << (8 - remainingBits)) & 0xFF;
    if ((view[fullBytes] & mask) !== 0) return false;
  }
  return true;
}

/**
 * Bucle de minería SHA-256. Usa self.crypto.subtle (API nativa del navegador).
 * Reporta progreso cada 500 intentos para actualizar la UI sin bloquear.
 */
async function mine(challenge, difficulty) {
  let nonce = 0;
  const startTime = Date.now();

  while (true) {
    const raw = ENCODER.encode(challenge + ':' + nonce);
    const hashBuffer = await self.crypto.subtle.digest('SHA-256', raw);

    if (meetsTarget(hashBuffer, difficulty)) {
      return { nonce, attempts: nonce + 1, timeMs: Date.now() - startTime };
    }

    nonce++;

    if (nonce % 500 === 0) {
      self.postMessage({ type: 'progress', attempts: nonce });
    }
  }
}

self.onmessage = async function(e) {
  try {
    const result = await mine(e.data.challenge, e.data.difficulty);
    self.postMessage({ type: 'solved', ...result });
  } catch (err) {
    self.postMessage({ type: 'error', message: String(err) });
  }
};
`;

// ─── Constantes ───────────────────────────────────────────────────────────────

/**
 * Dificultad del PoW en bits de cero iniciales del hash SHA-256.
 * 18 bits → ~262,144 hashes promedio → ~0.7-1.5 segundos en hardware moderno.
 */
const DIFFICULTY = 18;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateChallenge(bytes = 16): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function fmtNum(n: number): string {
  return n.toLocaleString('es-ES');
}

// ─── Componente ───────────────────────────────────────────────────────────────

export function CaptchaBox({ onVerifyChange, className = '' }: CaptchaBoxProps) {
  const [phase, setPhase] = useState<'idle' | 'computing' | 'verified'>('idle');
  const [attempts, setAttempts] = useState(0);
  const [timeMs, setTimeMs] = useState(0);
  const [challenge, setChallenge] = useState('');
  const workerRef = useRef<Worker | null>(null);
  const blobUrlRef = useRef<string>('');

  const terminate = () => {
    workerRef.current?.terminate();
    workerRef.current = null;
    if (blobUrlRef.current) {
      URL.revokeObjectURL(blobUrlRef.current);
      blobUrlRef.current = '';
    }
  };

  const reset = useCallback(() => {
    terminate();
    setChallenge(generateChallenge());
    setPhase('idle');
    setAttempts(0);
    setTimeMs(0);
    onVerifyChange(false);
  }, [onVerifyChange]);

  useEffect(() => {
    reset();
    return terminate;
  }, []);

  const startPoW = useCallback(() => {
    if (phase !== 'idle' || !challenge) return;

    setPhase('computing');
    setAttempts(0);

    const blob = new Blob([WORKER_CODE], { type: 'application/javascript' });
    const url = URL.createObjectURL(blob);
    blobUrlRef.current = url;

    const worker = new Worker(url);
    workerRef.current = worker;

    worker.onmessage = ({ data }: MessageEvent) => {
      if (data.type === 'progress') {
        setAttempts(data.attempts);
      } else if (data.type === 'solved') {
        setAttempts(data.attempts);
        setTimeMs(data.timeMs);
        setPhase('verified');
        onVerifyChange(true);
        terminate();
      } else if (data.type === 'error') {
        reset();
      }
    };

    worker.onerror = () => reset();
    worker.postMessage({ challenge, difficulty: DIFFICULTY });
  }, [challenge, phase, onVerifyChange, reset]);

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className={`pow-wrap ${className}`} role="group" aria-label="Verificación SHA-256 Proof of Work">

      {/* ── Estado: pendiente de verificar ── */}
      {phase === 'idle' && (
        <button
          type="button"
          className="pow-trigger-btn"
          onClick={startPoW}
          aria-label="Iniciar verificación criptográfica SHA-256"
        >
          <svg
            className="pow-shield-icon"
            width="15"
            height="15"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span>Verificar que soy humano</span>
          <span className="pow-algo-tag">SHA-256</span>
        </button>
      )}

      {/* ── Estado: calculando ── */}
      {phase === 'computing' && (
        <div className="pow-computing-row" aria-live="polite">
          <span className="pow-spinner" aria-hidden="true" />
          <div className="pow-computing-info">
            <span className="pow-computing-label">Calculando prueba criptográfica…</span>
            <span className="pow-computing-count">{fmtNum(attempts)} hashes SHA-256</span>
          </div>
          <div className="pow-bar-track" role="progressbar" aria-label="Progreso de verificación">
            <div className="pow-bar-fill" />
          </div>
        </div>
      )}

      {/* ── Estado: verificado ── */}
      {phase === 'verified' && (
        <div className="pow-verified-row">
          <div className="pow-check-icon" aria-hidden="true">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
              <path d="M20 6 9 17l-5-5" />
            </svg>
          </div>
          <div className="pow-verified-info">
            <span className="pow-verified-label">Verificado</span>
            <span className="pow-verified-meta">
              {fmtNum(attempts)} hashes · {timeMs} ms · {DIFFICULTY} bits SHA-256
            </span>
          </div>
          <button
            type="button"
            className="pow-reset-btn"
            onClick={reset}
            title="Regenerar desafío"
            aria-label="Regenerar desafío criptográfico"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2" />
            </svg>
          </button>
        </div>
      )}

    </div>
  );
}
