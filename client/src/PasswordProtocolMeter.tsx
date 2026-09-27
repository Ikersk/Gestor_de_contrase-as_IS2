import React from 'react';
import { evaluatePasswordProtocol } from './validation';

interface PasswordProtocolMeterProps {
  password?: string;
  minLength?: number;
  label?: string;
  className?: string;
  showWhenEmpty?: boolean;
}

const LEVEL_CONFIG = {
  'muy-debil': {
    color: 'bg-red-500',
    barColor: '#ef4444',
    text: 'text-red-500',
    border: 'border-red-500/30',
  },
  debil: {
    color: 'bg-amber-500',
    barColor: '#f59e0b',
    text: 'text-amber-500',
    border: 'border-amber-500/30',
  },
  media: {
    color: 'bg-blue-500',
    barColor: '#3b82f6',
    text: 'text-blue-500',
    border: 'border-blue-500/30',
  },
  fuerte: {
    color: 'bg-cyan-500',
    barColor: '#06b6d4',
    text: 'text-cyan-500',
    border: 'border-cyan-500/30',
  },
  excelente: {
    color: 'bg-emerald-500',
    barColor: '#10b981',
    text: 'text-emerald-500',
    border: 'border-emerald-500/30',
  },
};

export function PasswordProtocolMeter({
  password = '',
  minLength = 8,
  className = '',
  showWhenEmpty = false,
}: PasswordProtocolMeterProps) {
  if (!password && !showWhenEmpty) {
    return null;
  }

  const result = evaluatePasswordProtocol(password, minLength);
  const cfg = LEVEL_CONFIG[result.level];

  return (
    <div
      className={`password-protocol-box ${className}`}
      aria-live="polite"
      aria-label={`Entropía de contraseña: ${result.levelLabel}, ${result.entropy} bits`}
    >
      {/* Barra de progreso de entropía */}
      <div className="protocol-header">
        <div className="protocol-title-row">
          <span className="protocol-label">Seguridad y Entropía</span>
          <span className="protocol-entropy-badge" style={{ color: cfg.barColor }}>
            {result.levelLabel} ({result.entropy} bits)
          </span>
        </div>
        <div className="protocol-bar-track">
          <div
            className="protocol-bar-fill"
            style={{
              width: `${Math.max(5, result.score)}%`,
              backgroundColor: cfg.barColor,
              boxShadow: `0 0 10px ${cfg.barColor}55`,
            }}
          />
        </div>
      </div>

      {/* Lista interactiva de requisitos en tiempo real */}
      <div className="protocol-checklist">
        <div className={`protocol-item ${result.hasMinLength ? 'valid' : 'pending'}`}>
          <span className="protocol-check-icon">{result.hasMinLength ? '✓' : '•'}</span>
          <span>Mínimo {minLength} caracteres</span>
        </div>

        <div className={`protocol-item ${result.hasLower ? 'valid' : 'pending'}`}>
          <span className="protocol-check-icon">{result.hasLower ? '✓' : '•'}</span>
          <span>Minúscula (a-z)</span>
        </div>

        <div className={`protocol-item ${result.hasUpper ? 'valid' : 'pending'}`}>
          <span className="protocol-check-icon">{result.hasUpper ? '✓' : '•'}</span>
          <span>Mayúscula (A-Z)</span>
        </div>

        <div className={`protocol-item ${result.hasNumber ? 'valid' : 'pending'}`}>
          <span className="protocol-check-icon">{result.hasNumber ? '✓' : '•'}</span>
          <span>Número (0-9)</span>
        </div>

        <div className={`protocol-item ${result.hasSpecial ? 'valid' : 'pending'}`}>
          <span className="protocol-check-icon">{result.hasSpecial ? '✓' : '•'}</span>
          <span>Carácter especial (!@#$...)</span>
        </div>
      </div>
    </div>
  );
}
