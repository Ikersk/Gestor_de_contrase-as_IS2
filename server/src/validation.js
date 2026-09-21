const { z } = require('zod');

// Los límites de tamaño impiden payloads abusivos y reflejan el contrato del cliente.
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const AUTH_HASH_BYTES = 32;
const KDF_SALT_BYTES = 16;
const WRAP_IV_BYTES = 12;
const WRAPPED_VAULT_KEY_BYTES = 32 + 16;
const MAX_CIPHERTEXT_BYTES = 1_048_576;
const MAX_EMAIL_LENGTH = 254;

/** Acepta únicamente base64 canónico cuyo contenido cabe en el campo correspondiente. */
function base64String({ minBytes = 0, maxBytes = Number.POSITIVE_INFINITY } = {}) {
  return z.string().refine((value) => {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
    const decoded = Buffer.from(value, 'base64');
    return decoded.length >= minBytes
      && decoded.length <= maxBytes
      && decoded.toString('base64') === value;
  }, 'Must be canonical base64 with an allowed byte length');
}

// Normaliza emails para que registro, consulta de salt y login usen el mismo identificador.
const email = z.string().trim().toLowerCase().max(MAX_EMAIL_LENGTH).refine(
  (value) => EMAIL_PATTERN.test(value),
  'Must be a valid email',
);

const registerSchema = z.object({
  email,
  kdfSalt: base64String({ minBytes: KDF_SALT_BYTES, maxBytes: KDF_SALT_BYTES }),
  kdfIterations: z.number().int().min(100_000).max(2_000_000),
  authHash: base64String({ minBytes: AUTH_HASH_BYTES, maxBytes: AUTH_HASH_BYTES }),
  wrappedVaultKey: base64String({
    minBytes: WRAPPED_VAULT_KEY_BYTES,
    maxBytes: WRAPPED_VAULT_KEY_BYTES,
  }),
  wrapIv: base64String({ minBytes: WRAP_IV_BYTES, maxBytes: WRAP_IV_BYTES }),
});

const loginSchema = z.object({
  email,
  authHash: base64String({ minBytes: AUTH_HASH_BYTES, maxBytes: AUTH_HASH_BYTES }),
});

const changeMasterPasswordSchema = z.object({
  currentAuthHash: base64String({ minBytes: AUTH_HASH_BYTES, maxBytes: AUTH_HASH_BYTES }),
  kdfSalt: base64String({ minBytes: KDF_SALT_BYTES, maxBytes: KDF_SALT_BYTES }),
  kdfIterations: z.number().int().min(100_000).max(2_000_000),
  authHash: base64String({ minBytes: AUTH_HASH_BYTES, maxBytes: AUTH_HASH_BYTES }),
  wrappedVaultKey: base64String({
    minBytes: WRAPPED_VAULT_KEY_BYTES,
    maxBytes: WRAPPED_VAULT_KEY_BYTES,
  }),
  wrapIv: base64String({ minBytes: WRAP_IV_BYTES, maxBytes: WRAP_IV_BYTES }),
});

const deleteAccountSchema = z.object({
  authHash: base64String({ minBytes: AUTH_HASH_BYTES, maxBytes: AUTH_HASH_BYTES }),
});

const vaultItemSchema = z.object({
  iv: base64String({ minBytes: WRAP_IV_BYTES, maxBytes: WRAP_IV_BYTES }),
  ciphertext: base64String({ minBytes: 16, maxBytes: MAX_CIPHERTEXT_BYTES }),
});

/** Valida un cuerpo sin propagar detalles internos de Zod a la respuesta HTTP. */
function parsePayload(schema, body) {
  const result = schema.safeParse(body);
  return result.success ? result.data : null;
}

module.exports = {
  parsePayload,
  registerSchema,
  loginSchema,
  changeMasterPasswordSchema,
  deleteAccountSchema,
  vaultItemSchema,
};