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
  getAuthSalt,
  loginAccount,
  logoutAccount,
  registerAccount,
} from './api';
import { validateEmail, validateMasterPassword } from './validation';

let vaultKey: Uint8Array | null = null;
let activeKdfSalt: Uint8Array | null = null;
let activeKdfIterations: number | null = null;

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

/** Deriva el Auth Hash, inicia sesion y desenvuelve la Vault Key solo en memoria. */
export async function loginWithMasterPassword(email: string, masterPassword: string) {
  const emailError = validateEmail(email);
  const passwordError = validateMasterPassword(masterPassword);
  if (emailError) throw new Error(emailError);
  if (passwordError) throw new Error(passwordError);

  vaultKey = null;
  activeKdfSalt = null;
  activeKdfIterations = null;
  const { kdfSalt, kdfIterations } = await getAuthSalt(email);
  const salt = base64ToBytes(kdfSalt);
  const masterKey = await deriveMasterKey(
    masterPassword,
    salt,
    kdfIterations,
  );
  const { encryptionKey, authHash } = await deriveSubkeys(masterKey);
  const session = await loginAccount({ email, authHash });
  vaultKey = await unwrapVaultKey(encryptionKey, session.wrapIv, session.wrappedVaultKey);
  activeKdfSalt = salt;
  activeKdfIterations = kdfIterations;
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

  vaultKey = null;
  activeKdfSalt = null;
  activeKdfIterations = null;
}

/** Cierra la sesion remota y elimina la referencia local a la Vault Key. */
export async function logoutFromMemory() {
  try {
    await logoutAccount();
  } finally {
    vaultKey = null;
    activeKdfSalt = null;
    activeKdfIterations = null;
  }
}