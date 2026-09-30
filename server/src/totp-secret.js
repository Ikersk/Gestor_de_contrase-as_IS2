// Secreto TOTP de cuenta: generacion, cifrado en reposo y verificacion de codigos.
//
// El servidor DEBE conocer el secreto para poder verificar codigos RFC 6238, a
// diferencia del TOTP por credencial que vive dentro de la boveda cifrada. Por
// eso el secreto se guarda cifrado con una clave propia de la servidor
// (TOTP_ENC_KEY): quien robe solo la base de datos no obtiene secretos utiles.
const crypto = require('node:crypto');
const { Secret, TOTP, URI } = require('otpauth');

const TOTP_PERIOD_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_SECRET_BYTES = 20; // 160 bits, longitud recomendada por RFC 4226 para HMAC-SHA1.
const TOTP_IV_BYTES = 12; // IV de 12 bytes exigido por AES-GCM.
const TOTP_KEY_BYTES = 32; // AES-256.
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Clave AES-256 que protege los secretos TOTP en la base de datos. */
function getTotpKey() {
  const raw = process.env.TOTP_ENC_KEY;
  if (!raw) {
    const error = new Error('TOTP_ENC_KEY must be set to enable MFA');
    error.code = 'TOTP_KEY_MISSING';
    throw error;
  }
  const key = Buffer.from(raw, 'base64');
  // Se exige que la clave decodifique a exactamente 32 bytes para evitar claves
  // debiles por cadenas que "parecen" base64 pero aportan poca entropia.
  if (key.length !== TOTP_KEY_BYTES) {
    const error = new Error('TOTP_ENC_KEY must be a base64 string of exactly 32 bytes');
    error.code = 'TOTP_KEY_INVALID';
    throw error;
  }
  return key;
}

/** Codifica bytes a base32 RFC 4648 sin padding (formato aceptado por las apps authenticator). */
function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

/** Genera un secreto TOTP aleatorio criptografico de 160 bits en base32. */
function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(TOTP_SECRET_BYTES));
}

/** Cifra el secreto con AES-256-GCM y un IV nuevo; formato base64(iv):base64(ciphertext+tag). */
function encryptSecret(plainSecret) {
  const iv = crypto.randomBytes(TOTP_IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', getTotpKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plainSecret, 'utf8'), cipher.final()]);
  const sealed = Buffer.concat([ciphertext, cipher.getAuthTag()]);
  return `${iv.toString('base64')}:${sealed.toString('base64')}`;
}

/** Descifra un secreto almacenado; falla si la clave o el ciphertext fueron alterados. */
function decryptSecret(storedSecret) {
  const [ivPart, sealedPart] = String(storedSecret).split(':');
  if (!ivPart || !sealedPart) {
    throw new Error('Stored TOTP secret is malformed');
  }
  const iv = Buffer.from(ivPart, 'base64');
  const sealed = Buffer.from(sealedPart, 'base64');
  if (iv.length !== TOTP_IV_BYTES || sealed.length <= 16) {
    throw new Error('Stored TOTP secret is malformed');
  }
  const tag = sealed.subarray(sealed.length - 16);
  const ciphertext = sealed.subarray(0, sealed.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', getTotpKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/** Construye el objeto TOTP con los parametros fijados del proyecto (SHA1/6/30s). */
function createTotpInstance(base32Secret, email) {
  return new TOTP({
    issuer: 'Arca',
    label: email,
    secret: Secret.fromBase32(base32Secret),
    algorithm: 'SHA1',
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD_SECONDS,
  });
}

/** URI otpauth:// que escanean las apps authenticator para registrar la cuenta. */
function buildOtpauthUri(base32Secret, email) {
  return URI.stringify(createTotpInstance(base32Secret, email));
}

/**
 * Verifica un codigo contra el secreto y devuelve el contador (time-step) validado.
 *
 * Se prueban los vecinos ±1 paso (30s de tolerancia de reloj). La comparacion es
 * de tiempo constante con crypto.timingSafeEqual y no hay "early return" para que
 * el tiempo de respuesta no delate en que ventana encajo el codigo.
 * Devuelve `null` si el codigo no es valido.
 */
function verifyTotpCode(base32Secret, code, { window = 1, now = Date.now() } = {}) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null;

  let totp;
  try {
    totp = createTotpInstance(base32Secret, 'verify@arca.local');
  } catch {
    return null;
  }

  const center = Math.floor(now / (TOTP_PERIOD_SECONDS * 1000));
  let matchedCounter = null;
  const expectedBuffer = Buffer.alloc(TOTP_DIGITS);
  const codeBuffer = Buffer.from(code, 'utf8');

  for (let delta = -window; delta <= window; delta += 1) {
    const counter = center + delta;
    if (counter < 0) continue;
    const expected = totp.generate({ timestamp: counter * TOTP_PERIOD_SECONDS * 1000 });
    expectedBuffer.write(expected, 'utf8');
    const equal = crypto.timingSafeEqual(expectedBuffer, codeBuffer);
    // Se recorren todas las ventanas siempre, pero solo se conserva el primer acierto.
    if (equal && matchedCounter === null) matchedCounter = counter;
  }

  return matchedCounter;
}

module.exports = {
  TOTP_PERIOD_SECONDS,
  TOTP_DIGITS,
  base32Encode,
  generateTotpSecret,
  encryptSecret,
  decryptSecret,
  buildOtpauthUri,
  verifyTotpCode,
};
