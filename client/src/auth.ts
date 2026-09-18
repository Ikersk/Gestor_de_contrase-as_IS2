// Flujo criptografico de registro y login. La Vault Key nunca se escribe en Web Storage.
import {
  DEFAULT_KDF_ITERATIONS,
  base64ToBytes,
  bytesToBase64,
  deriveMasterKey,
  deriveSubkeys,
  randomBytes,
} from './crypto/kdf.js';
import { generateVaultKey, unwrapVaultKey, wrapVaultKey } from './crypto/vault-key.js';
import { getAuthSalt, loginAccount, logoutAccount, registerAccount } from './api';

let vaultKey: Uint8Array | null = null;

/** Devuelve la Vault Key activa solo para que las siguientes fases cifren items en memoria. */
export function getVaultKey() {
  return vaultKey;
}

/** Deriva el material de autenticacion y envuelve una nueva Vault Key durante el registro. */
export async function registerWithMasterPassword(email: string, masterPassword: string) {
  const salt = randomBytes(16);
  const masterKey = await deriveMasterKey(masterPassword, salt, DEFAULT_KDF_ITERATIONS);
  const { encryptionKey, authHash } = await deriveSubkeys(masterKey);
  const createdVaultKey = generateVaultKey();
  const wrapped = await wrapVaultKey(encryptionKey, createdVaultKey);

  await registerAccount({
    email,
    kdfSalt: bytesToBase64(salt),
    kdfIterations: DEFAULT_KDF_ITERATIONS,
    authHash,
    wrappedVaultKey: wrapped.wrappedVaultKey,
    wrapIv: wrapped.wrapIv,
  });
}

/** Deriva el Auth Hash, inicia sesion y desenvuelve la Vault Key solo en memoria. */
export async function loginWithMasterPassword(email: string, masterPassword: string) {
  vaultKey = null;
  const { kdfSalt, kdfIterations } = await getAuthSalt(email);
  const masterKey = await deriveMasterKey(
    masterPassword,
    base64ToBytes(kdfSalt),
    kdfIterations,
  );
  const { encryptionKey, authHash } = await deriveSubkeys(masterKey);
  const session = await loginAccount({ email, authHash });
  vaultKey = await unwrapVaultKey(encryptionKey, session.wrapIv, session.wrappedVaultKey);
}

/** Cierra la sesion remota y elimina la referencia local a la Vault Key. */
export async function logoutFromMemory() {
  try {
    await logoutAccount();
  } finally {
    vaultKey = null;
  }
}