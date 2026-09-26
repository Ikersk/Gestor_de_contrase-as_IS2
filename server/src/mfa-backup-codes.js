// Codigos de respaldo de un solo uso: permiten entrar si se pierde el
// dispositivo TOTP. Se guardan hasheados con bcrypt y se muestran una sola vez.
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const { base32Encode } = require('./totp-secret');

const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_BYTES = 5; // 40 bits -> exactamente 8 caracteres base32.
const BACKUP_CODE_COST = 12; // Mismo coste que el Auth Hash en el resto del sistema.
const BACKUP_CODE_PATTERN = /^[A-Z0-9]{8}$/;

/** Forma canonica: mayusculas y sin separadores, para que "abcd-efgh" case con "ABCDEFGH". */
function normalizeBackupCode(value) {
  return typeof value === 'string' ? value.toUpperCase().replace(/[^A-Z0-9]/g, '') : '';
}

/** Genera los codigos en formato XXXX-XXXX usando aleatoriedad criptografica. */
function generateBackupCodes() {
  const codes = [];
  for (let index = 0; index < BACKUP_CODE_COUNT; index += 1) {
    const raw = base32Encode(crypto.randomBytes(BACKUP_CODE_BYTES));
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
  }
  return codes;
}

/** Hashea el codigo normalizado para almacenarlo; nunca se guarda el codigo en claro. */
function hashBackupCode(code) {
  return bcrypt.hash(normalizeBackupCode(code), BACKUP_CODE_COST);
}

/**
 * Busca un codigo entre los hashes pendientes y devuelve la fila coincidente o null.
 * Se comparan todos los hashes siempre (sin early return) para que el tiempo de
 * respuesta no delate si el fallo fue por formato o por no coincidir.
 */
async function findMatchingBackupCode(code, codeRows) {
  const normalized = normalizeBackupCode(code);
  if (!BACKUP_CODE_PATTERN.test(normalized)) return null;

  let matchedRow = null;
  for (const row of codeRows) {
    const equal = await bcrypt.compare(normalized, row.code_hash);
    if (equal && matchedRow === null) matchedRow = row;
  }
  return matchedRow;
}

module.exports = {
  BACKUP_CODE_COUNT,
  normalizeBackupCode,
  generateBackupCodes,
  hashBackupCode,
  findMatchingBackupCode,
};
