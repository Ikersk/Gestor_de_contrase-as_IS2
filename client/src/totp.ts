import { Secret, TOTP, URI } from "otpauth";

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;

const BASE32_PATTERN = /^[A-Z2-7]+=*$/;

/** Limpia un secreto pegado desde un autenticador y extrae secretos de URIs otpauth. */
export function normalizeTotpSecret(value: string) {
  const compactValue = value.trim().replace(/\s+/g, "");
  if (!compactValue) return "";

  if (compactValue.toLowerCase().startsWith("otpauth://")) {
    return URI.parse(compactValue).secret.base32;
  }

  return compactValue.toUpperCase();
}

export function isValidTotpSecret(value: string) {
  if (!value) return true;
  try {
    const normalized = normalizeTotpSecret(value);
    return Boolean(normalized) && BASE32_PATTERN.test(normalized) && normalized.length >= 8;
  } catch {
    return false;
  }
}

export function createTotp(secret: string) {
  return new TOTP({
    secret: Secret.fromBase32(normalizeTotpSecret(secret)),
    algorithm: "SHA1",
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD_SECONDS,
  });
}

export function getTotpSnapshot(secret: string, timestamp = Date.now()) {
  const totp = createTotp(secret);
  const remainingMilliseconds = TOTP.remaining({
    period: TOTP_PERIOD_SECONDS,
    timestamp,
  });

  return {
    code: totp.generate({ timestamp }),
    remainingSeconds: Math.ceil(remainingMilliseconds / 1000),
    progress: remainingMilliseconds / (TOTP_PERIOD_SECONDS * 1000),
  };
}