export const FIELD_LIMITS = {
  email: 40,
  masterPassword: 42,
  title: 30,
  username: 30,
  password: 32,
  url: 100,
} as const;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export interface ValidatableCredential {
  title: string;
  username: string;
  password: string;
  url: string;
}

function requiredText(value: string, label: string, maxLength: number, requireLetter = false) {
  if (!value.trim()) return `${label} es obligatorio`;
  if (value.length > maxLength) return `${label} no puede superar ${maxLength} caracteres`;
  if (requireLetter && !/\p{L}/u.test(value)) return `${label} debe contener al menos una letra`;
  return null;
}

export function validateEmail(value: string) {
  const email = value.trim();
  if (!email) return 'El correo electronico es obligatorio';
  if (email.length > FIELD_LIMITS.email) return `El correo electronico no puede superar ${FIELD_LIMITS.email} caracteres`;
  if (!EMAIL_PATTERN.test(email)) return 'Introduce un correo electronico valido';
  return null;
}

export function validateMasterPassword(value: string) {
  if (!value) return 'La contrasena maestra es obligatoria';
  if (value.length < 12) return 'La contrasena maestra debe tener al menos 12 caracteres';
  if (value.length > FIELD_LIMITS.masterPassword) return `La contrasena maestra no puede superar ${FIELD_LIMITS.masterPassword} caracteres`;
  return null;
}

export function validateCredential(credential: ValidatableCredential) {
  const checks = [
    requiredText(credential.title, 'El nombre', FIELD_LIMITS.title, true),
    requiredText(credential.username, 'El usuario', FIELD_LIMITS.username, true),
    requiredText(credential.password, 'La contrasena', FIELD_LIMITS.password),
  ];
  const firstError = checks.find(Boolean);
  if (firstError) return firstError;

  if (credential.url.length > FIELD_LIMITS.url) {
    return `La URL no puede superar ${FIELD_LIMITS.url} caracteres`;
  }
  if (credential.url) {
    try {
      const parsedUrl = new URL(credential.url);
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return 'La URL debe comenzar por http:// o https://';
      }
    } catch {
      return 'Introduce una URL valida';
    }
  }
  return null;
}