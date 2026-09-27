// Flujo criptografico de registro y login. La Vault Key nunca se escribe en Web Storage.
import {
  DEFAULT_KDF_ITERATIONS,
  KDF_SALT_BYTES,
  base64ToBytes,
  bytesToBase64,
  deriveMasterKey,
  deriveSubkeys,
  randomBytes,
} from './crypto/kdf.js';
import { generateVaultKey, unwrapVaultKey, wrapVaultKey } from './crypto/vault-key.js';
import {
  changeMasterPasswordRequest,
  deleteAccount,
  getAuthSalt,
  loginAccount,
  logoutAccount,
  registerAccount,
  verifyMfaLogin,
} from './api';
import { validateEmail, validateMasterPassword } from './validation';

let vaultKey: Uint8Array | null = null;
let activeKdfSalt: Uint8Array | null = null;
let activeKdfIterations: number | null = null;

// Material derivado retenido entre el primer paso del login (contraseña correcta)
// y la verificación del segundo factor. Vive solo en memoria, igual que vaultKey.
let pendingEncryptionKey: CryptoKey | null = null;
let pendingSalt: Uint8Array | null = null;
let pendingIterations: number | null = null;

/** Descarta el reto MFA pendiente (al empezar otro login o al cerrar sesión). */
function clearPendingMfa() {
  pendingEncryptionKey = null;
  pendingSalt = null;
  pendingIterations = null;
}

function clearActiveKeys() {
  vaultKey = null;
  activeKdfSalt = null;
  activeKdfIterations = null;
  clearPendingMfa();
}

/** Devuelve la Vault Key activa solo para que las siguientes fases cifren items en memoria. */
export function getVaultKey() {
  return vaultKey;
}

/** Deriva el material de autenticacion y envuelve una nueva Vault Key durante el registro. */
export async function registerWithMasterPassword(email: string, masterPassword: string) {
  const emailError = validateEmail(email);
  const passwordError = validateMasterPassword(masterPassword);
  if (emailError) throw new Error(emailError);
  if (passwordError) throw new Error(passwordError);

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

/** Deriva el Auth Hash e inicia sesión; devuelve 'mfa-required' si falta el segundo factor. */
export async function loginWithMasterPassword(email: string, masterPassword: string) {
  const emailError = validateEmail(email);
  const passwordError = validateMasterPassword(masterPassword);
  if (emailError) throw new Error(emailError);
  if (passwordError) throw new Error(passwordError);

  vaultKey = null;
  activeKdfSalt = null;
  activeKdfIterations = null;
  clearPendingMfa();

  const { kdfSalt, kdfIterations } = await getAuthSalt(email);
  const salt = base64ToBytes(kdfSalt);
  const masterKey = await deriveMasterKey(
    masterPassword,
    salt,
    kdfIterations,
  );
  const { encryptionKey, authHash } = await deriveSubkeys(masterKey);
  const session = await loginAccount({ email, authHash });

  if ('mfaRequired' in session) {
    // Sin MFA el servidor no devuelve el blob de la vault key: se conserva solo
    // el material derivado para desenvolverla cuando llegue el código TOTP.
    pendingEncryptionKey = encryptionKey;
    pendingSalt = salt;
    pendingIterations = kdfIterations;
    return 'mfa-required' as const;
  }

  vaultKey = await unwrapVaultKey(encryptionKey, session.wrapIv, session.wrappedVaultKey);
  activeKdfSalt = salt;
  activeKdfIterations = kdfIterations;
  return 'ok' as const;
}

/**
 * Completa el login tras el código TOTP o de respaldo y desenvuelve la Vault Key.
 * Un código incorrecto no destruye el reto: permite reintentar hasta que la
 * cookie intermedia `mfa` caduque en el servidor.
 */
export async function completeMfaLogin(code: string) {
  if (!pendingEncryptionKey || !pendingSalt || pendingIterations === null) {
    throw new Error('El reto de verificación ya no está disponible. Inicia sesión de nuevo.');
  }

  const session = await verifyMfaLogin({ code });
  vaultKey = await unwrapVaultKey(pendingEncryptionKey, session.wrapIv, session.wrappedVaultKey);
  activeKdfSalt = pendingSalt;
  activeKdfIterations = pendingIterations;
  clearPendingMfa();
}

/** Rota el material de autenticacion y vuelve a envolver la Vault Key existente. */
export async function changeMasterPassword(currentPassword: string, newPassword: string) {
  if (!vaultKey || !activeKdfSalt || activeKdfIterations === null) {
    throw new Error('La sesión no está disponible');
  }

  const currentPasswordError = validateMasterPassword(currentPassword);
  const newPasswordError = validateMasterPassword(newPassword);
  if (currentPasswordError) throw new Error(currentPasswordError);
  if (newPasswordError) throw new Error(newPasswordError);
  if (currentPassword === newPassword) {
    throw new Error('La nueva contraseña debe ser diferente');
  }

  const currentMasterKey = await deriveMasterKey(
    currentPassword,
    activeKdfSalt,
    activeKdfIterations,
  );
  const { authHash: currentAuthHash } = await deriveSubkeys(currentMasterKey);
  const newSalt = randomBytes(KDF_SALT_BYTES);
  const newMasterKey = await deriveMasterKey(
    newPassword,
    newSalt,
    DEFAULT_KDF_ITERATIONS,
  );
  const { encryptionKey, authHash } = await deriveSubkeys(newMasterKey);
  const wrapped = await wrapVaultKey(encryptionKey, vaultKey);

  await changeMasterPasswordRequest({
    currentAuthHash,
    kdfSalt: bytesToBase64(newSalt),
    kdfIterations: DEFAULT_KDF_ITERATIONS,
    authHash,
    wrappedVaultKey: wrapped.wrappedVaultKey,
    wrapIv: wrapped.wrapIv,
  });

  clearActiveKeys();
}

/** Cierra la sesion remota y elimina la referencia local a la Vault Key. */
export async function logoutFromMemory() {
  try {
    await logoutAccount();
  } finally {
    clearActiveKeys();
  }
}

/** Elimina la cuenta en el servidor y destruye la Vault Key en memoria. */
export async function deleteAccountFromPassword(currentPassword: string) {
  if (!vaultKey || !activeKdfSalt || activeKdfIterations === null) {
    throw new Error('La sesión no está disponible');
  }

  const masterKey = await deriveMasterKey(currentPassword, activeKdfSalt, activeKdfIterations);
  const { authHash } = await deriveSubkeys(masterKey);

  try {
    await deleteAccount({ authHash });
  } finally {
    clearActiveKeys();
  }
}