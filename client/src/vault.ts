// Puente entre la UI y el CRUD: cifra antes de enviar y descifra despues de recibir.
import { decryptItem, encryptItem } from './crypto/cipher.js';
import { createVaultItem, deleteVaultItem, getVaultItems, updateVaultItem } from './api';
import { getVaultKey } from './auth';
import { validateCredential } from './validation';

export interface Credential {
  title: string;
  username: string;
  password: string;
  url: string;
}

export interface DecryptedCredential extends Credential {
  id: number | string;
}

function requireVaultKey() {
  const vaultKey = getVaultKey();
  if (!vaultKey) throw new Error('La boveda esta bloqueada');
  return vaultKey;
}

/** Descarga blobs y descifra cada credencial exclusivamente en el navegador. */
export async function listCredentials(): Promise<DecryptedCredential[]> {
  const vaultKey = requireVaultKey();
  const items = await getVaultItems();
  return Promise.all(items.map(async (item) => ({
    id: item.id,
    ...(await decryptItem(vaultKey, item.iv, item.ciphertext) as Credential),
  })));
}

/** Cifra una credencial y la crea en la API sin enviar sus campos legibles. */
export async function createCredential(entry: Credential) {
  const validationError = validateCredential(entry);
  if (validationError) throw new Error(validationError);
  const encrypted = await encryptItem(requireVaultKey(), entry);
  const created = await createVaultItem(encrypted);
  return { id: created.id, ...entry };
}

/** Cifra de nuevo una credencial editada para que cada escritura use un IV nuevo. */
export async function updateCredential(id: number | string, entry: Credential) {
  const validationError = validateCredential(entry);
  if (validationError) throw new Error(validationError);
  const encrypted = await encryptItem(requireVaultKey(), entry);
  await updateVaultItem(id, encrypted);
  return { id, ...entry };
}

/** Elimina un blob cifrado de la API. */
export function removeCredential(id: number | string) {
  return deleteVaultItem(id);
}