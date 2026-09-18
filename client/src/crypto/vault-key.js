// Gestion de la Vault Key: se cifra una vez con la Encryption Key y se conserva solo en memoria.
import {
  AES_KEY_BYTES,
  base64ToBytes,
  bytesToBase64,
  randomBytes,
} from './kdf.js';

export const AES_GCM_IV_BYTES = 12;

/** Convierte entradas binarias a Uint8Array antes de pasarlas a Web Crypto. */
function asBytes(value) {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

/** Verifica que una clave o IV cumple el tamano del protocolo. */
function assertByteLength(value, expectedLength, label) {
  if (asBytes(value).byteLength !== expectedLength) {
    throw new Error(`${label} must be exactly ${expectedLength} bytes`);
  }
}

/** Importa una Vault Key cruda como clave AES-GCM con el uso solicitado. */
async function importVaultKey(vaultKey, usages) {
  assertByteLength(vaultKey, AES_KEY_BYTES, 'Vault key');

  return crypto.subtle.importKey(
    'raw',
    asBytes(vaultKey),
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}

/** Crea la clave aleatoria que cifrara todos los elementos de una boveda. */
export function generateVaultKey() {
  return randomBytes(AES_KEY_BYTES);
}

/** Envuelve la Vault Key con AES-GCM para poder almacenarla junto a la cuenta. */
export async function wrapVaultKey(encryptionKey, vaultKey, wrapIv = randomBytes(AES_GCM_IV_BYTES)) {
  assertByteLength(wrapIv, AES_GCM_IV_BYTES, 'Wrap IV');
  const encryptedVaultKey = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: asBytes(wrapIv), tagLength: 128 },
    encryptionKey,
    asBytes(vaultKey),
  );

  return {
    wrapIv: bytesToBase64(wrapIv),
    wrappedVaultKey: bytesToBase64(encryptedVaultKey),
  };
}

/** Recupera la Vault Key en memoria descifrando el blob devuelto durante el login. */
export async function unwrapVaultKey(encryptionKey, wrapIv, wrappedVaultKey) {
  const iv = base64ToBytes(wrapIv);
  const ciphertext = base64ToBytes(wrappedVaultKey);
  assertByteLength(iv, AES_GCM_IV_BYTES, 'Wrap IV');

  const vaultKey = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    encryptionKey,
    ciphertext,
  );
  const bytes = new Uint8Array(vaultKey);
  assertByteLength(bytes, AES_KEY_BYTES, 'Unwrapped vault key');
  return bytes;
}

export { importVaultKey };
