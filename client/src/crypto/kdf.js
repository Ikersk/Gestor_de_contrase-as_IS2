const textEncoder = new TextEncoder();

export const DEFAULT_KDF_ITERATIONS = 600_000;
export const KDF_SALT_BYTES = 16;
export const AES_KEY_BYTES = 32;

function asBytes(value) {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function assertByteLength(value, expectedLength, label) {
  if (asBytes(value).byteLength !== expectedLength) {
    throw new Error(`${label} must be exactly ${expectedLength} bytes`);
  }
}

export function randomBytes(length) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error('Random byte length must be a positive integer');
  }

  return crypto.getRandomValues(new Uint8Array(length));
}

export function bytesToBase64(value) {
  const bytes = asBytes(value);
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

export function base64ToBytes(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('Base64 value must be a non-empty string');
  }

  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new Error('Invalid base64 value');
  }

  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export async function deriveMasterKey(
  password,
  salt,
  iterations = DEFAULT_KDF_ITERATIONS,
) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('Master password must be a non-empty string');
  }
  assertByteLength(salt, KDF_SALT_BYTES, 'KDF salt');
  if (!Number.isInteger(iterations) || iterations <= 0) {
    throw new Error('KDF iterations must be a positive integer');
  }

  const passwordKey = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );

  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: asBytes(salt),
        iterations,
      },
      passwordKey,
      AES_KEY_BYTES * 8,
    ),
  );
}

export async function deriveSubkeys(masterKey) {
  assertByteLength(masterKey, AES_KEY_BYTES, 'Master key');

  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    asBytes(masterKey),
    'HKDF',
    false,
    ['deriveBits'],
  );

  const deriveContextKey = (context) =>
    crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: textEncoder.encode(context),
      },
      hkdfKey,
      AES_KEY_BYTES * 8,
    );

  const [encryptionKeyBits, authKeyBits] = await Promise.all([
    deriveContextKey('enc'),
    deriveContextKey('auth'),
  ]);
  const authKeyMaterial = new Uint8Array(authKeyBits);
  const encryptionKey = await crypto.subtle.importKey(
    'raw',
    encryptionKeyBits,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );

  return {
    encryptionKey,
    authKeyMaterial,
    authHash: bytesToBase64(authKeyMaterial),
  };
}
