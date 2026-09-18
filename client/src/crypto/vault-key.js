import {
  AES_KEY_BYTES,
  base64ToBytes,
  bytesToBase64,
  randomBytes,
} from './kdf.js';

export const AES_GCM_IV_BYTES = 12;

function asBytes(value) {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function assertByteLength(value, expectedLength, label) {
  if (asBytes(value).byteLength !== expectedLength) {
    throw new Error(`${label} must be exactly ${expectedLength} bytes`);
  }
}

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

export function generateVaultKey() {
  return randomBytes(AES_KEY_BYTES);
}

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
