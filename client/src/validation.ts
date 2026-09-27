// Mantiene los límites de la interfaz alineados con el tamaño esperado por el protocolo.
import { isValidTotpSecret, normalizeTotpSecret } from './totp';

export const FIELD_LIMITS = {
  email: 40,
  masterPassword: 42,
  title: 30,
  username: 30,
  password: 32,
  totpSecret: 128,
  url: 100,
  maxUrls: 8,
} as const;

// Comprueba una forma básica de correo sin intentar implementar toda la especificación RFC.
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export interface ValidatableCredential {
  title: string;
  username: string;
  password: string;
  urls: string[];
  totpSecret?: string;
}

/** Valida campos obligatorios y, cuando procede, evita valores compuestos solo por símbolos. */
function requiredText(value: string, label: string, maxLength: number, requireLetter = false) {
  if (!value.trim()) return `${label} es obligatorio`;
  if (value.length > maxLength) return `${label} no puede superar ${maxLength} caracteres`;
  if (requireLetter && !/\p{L}/u.test(value)) return `${label} debe contener al menos una letra`;
  return null;
}

/** Valida el correo antes de iniciar cualquier operación criptográfica o de red. */
export function validateEmail(value: string) {
  const email = value.trim();
  if (!email) return 'El correo electronico es obligatorio';
  if (email.length > FIELD_LIMITS.email) return `El correo electronico no puede superar ${FIELD_LIMITS.email} caracteres`;
  if (!EMAIL_PATTERN.test(email)) return 'Introduce un correo electronico valido';
  return null;
}

/** Aplica la longitud mínima y máxima de la contraseña maestra sin inspeccionar su contenido. */
export function validateMasterPassword(value: string) {
  if (!value) return 'La contrasena maestra es obligatoria';
  if (value.length < 12) return 'La contrasena maestra debe tener al menos 12 caracteres';
  if (value.length > FIELD_LIMITS.masterPassword) return `La contrasena maestra no puede superar ${FIELD_LIMITS.masterPassword} caracteres`;
  return null;
}

export interface PasswordProtocolResult {
  hasLower: boolean;
  hasUpper: boolean;
  hasNumber: boolean;
  hasSpecial: boolean;
  hasMinLength: boolean;
  entropy: number;
  score: number;
  level: 'muy-debil' | 'debil' | 'media' | 'fuerte' | 'excelente';
  levelLabel: string;
  isValid: boolean;
  errors: string[];
}

/** Evalúa en tiempo real si una contraseña cumple con el protocolo de seguridad y calcula su entropía en bits. */
export function evaluatePasswordProtocol(password: string, minLength = 8): PasswordProtocolResult {
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  const hasMinLength = password.length >= minLength;

  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasNumber) poolSize += 10;
  if (hasSpecial) poolSize += 33;

  const entropy = password.length > 0 && poolSize > 0 
    ? Math.round(password.length * Math.log2(poolSize)) 
    : 0;

  const criteria = [hasLower, hasUpper, hasNumber, hasSpecial, hasMinLength];
  const passedCount = criteria.filter(Boolean).length;
  const score = Math.min(100, Math.round((passedCount / 5) * 60 + Math.min(40, (entropy / 80) * 40)));

  let level: PasswordProtocolResult['level'] = 'muy-debil';
  let levelLabel = 'Muy Débil';
  if (score >= 85 && passedCount === 5) {
    level = 'excelente';
    levelLabel = 'Excelente';
  } else if (score >= 70 && passedCount >= 4) {
    level = 'fuerte';
    levelLabel = 'Fuerte';
  } else if (score >= 50 && passedCount >= 3) {
    level = 'media';
    levelLabel = 'Media';
  } else if (score >= 25) {
    level = 'debil';
    levelLabel = 'Débil';
  }

  const errors: string[] = [];
  if (!hasMinLength) errors.push(`Mínimo ${minLength} caracteres`);
  if (!hasLower) errors.push('Al menos una letra minúscula (a-z)');
  if (!hasUpper) errors.push('Al menos una letra mayúscula (A-Z)');
  if (!hasNumber) errors.push('Al menos un número (0-9)');
  if (!hasSpecial) errors.push('Al menos un carácter especial (!@#$%...)');

  return {
    hasLower,
    hasUpper,
    hasNumber,
    hasSpecial,
    hasMinLength,
    entropy,
    score,
    level,
    levelLabel,
    isValid: passedCount === 5,
    errors,
  };
}

export function validateSecurePassword(value: string, minLength = 8, label = 'La contraseña') {
  if (!value) return `${label} es obligatoria`;
  const result = evaluatePasswordProtocol(value, minLength);
  if (!result.isValid && result.errors.length > 0) {
    return `${label} debe cumplir el protocolo de seguridad: ${result.errors[0]}`;
  }
  return null;
}

/** Valida los campos legibles de una credencial antes de cifrarlos y guardarlos. */
export function validateCredential(credential: ValidatableCredential) {
  const checks = [
    requiredText(credential.title, 'El nombre', FIELD_LIMITS.title, true),
    requiredText(credential.username, 'El usuario', FIELD_LIMITS.username, true),
    requiredText(credential.password, 'La contrasena', FIELD_LIMITS.password),
  ];
  const firstError = checks.find(Boolean);
  if (firstError) return firstError;

  if (credential.totpSecret && credential.totpSecret.length > FIELD_LIMITS.totpSecret) {
    return `El secreto TOTP no puede superar ${FIELD_LIMITS.totpSecret} caracteres`;
  }
  if (credential.totpSecret && !isValidTotpSecret(credential.totpSecret)) {
    return 'Introduce un secreto TOTP Base32 válido o una URI otpauth válida';
  }

  if (credential.urls.length === 0) {
    return 'Debes añadir al menos una URL';
  }
  if (credential.urls.length > FIELD_LIMITS.maxUrls) {
    return `No puedes añadir más de ${FIELD_LIMITS.maxUrls} URLs`;
  }
  for (const url of credential.urls) {
    if (!url) continue;
    if (url.length > FIELD_LIMITS.url) {
      return `Cada URL debe tener entre 1 y ${FIELD_LIMITS.url} caracteres`;
    }
    try {
      const parsedUrl = new URL(url);
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return 'Las URLs deben comenzar por http:// o https://';
      }
    } catch {
      return 'Introduce URLs validas';
    }
  }
  return null;
}