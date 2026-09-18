import {
  AES_KEY_BYTES,
  base64ToBytes,
  bytesToBase64,
  randomBytes,
} from './kdf.js';
import { AES_GCM_IV_BYTES, importVaultKey } from './vault-key.js';

function asBytes(value) {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function serializeEntry(entry) {
  try {
    return JSON.stringify(entry);
  } catch {
    throw new Error('Vault entry must be JSON serializable');
  }
}

export async function encryptItem(vaultKey, entry, iv = randomBytes(AES_GCM_IV_BYTES)) {
  if (iv.byteLength !== AES_GCM_IV_BYTES) {
    throw new Error(`Item IV must be exactly ${AES_GCM_IV_BYTES} bytes`);
  }

  const key = await importVaultKey(vaultKey, ['encrypt']);
  const plaintext = new TextEncoder().encode(serializeEntry(entry));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: asBytes(iv), tagLength: 128 },
    key,
    plaintext,
  );

  return {
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(ciphertext),
  };
}

export async function decryptItem(vaultKey, iv, ciphertext) {
  const itemIv = base64ToBytes(iv);
  const encryptedValue = base64ToBytes(ciphertext);
  if (itemIv.byteLength !== AES_GCM_IV_BYTES) {
    throw new Error(`Item IV must be exactly ${AES_GCM_IV_BYTES} bytes`);
  }

  const key = await importVaultKey(vaultKey, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: itemIv, tagLength: 128 },
    key,
    encryptedValue,
  );

  try {
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new Error('Decrypted vault item is not valid JSON');
  }
}

export { AES_KEY_BYTES };
