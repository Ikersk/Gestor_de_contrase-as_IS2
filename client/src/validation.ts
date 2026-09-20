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