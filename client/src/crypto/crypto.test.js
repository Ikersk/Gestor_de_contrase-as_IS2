import { describe, expect, it } from 'vitest';
import {
  DEFAULT_KDF_ITERATIONS,
  deriveMasterKey,
  deriveSubkeys,
  randomBytes,
} from './kdf.js';
import {
  generateVaultKey,
  unwrapVaultKey,
  wrapVaultKey,
} from './vault-key.js';
import { decryptItem, encryptItem } from './cipher.js';

describe('client cryptography', () => {
  it('derives separate encryption and authentication material', async () => {
    const salt = new Uint8Array(16).fill(7);
    const masterKey = await deriveMasterKey(
      'correct horse battery staple',
      salt,
      DEFAULT_KDF_ITERATIONS,
    );
    const subkeys = await deriveSubkeys(masterKey);

    expect(masterKey).toHaveLength(32);
    expect(subkeys.authKeyMaterial).toHaveLength(32);
    expect(subkeys.authHash).toBeTruthy();
    expect(subkeys.encryptionKey.type).toBe('secret');
  });

  it('wraps and unwraps the vault key', async () => {
    const masterKey = await deriveMasterKey('test password', new Uint8Array(16).fill(3), 1_000);
    const { encryptionKey } = await deriveSubkeys(masterKey);
    const vaultKey = generateVaultKey();
    const wrapIv = new Uint8Array(12).fill(9);
    const wrapped = await wrapVaultKey(encryptionKey, vaultKey, wrapIv);
    const unwrapped = await unwrapVaultKey(
      encryptionKey,
      wrapped.wrapIv,
      wrapped.wrappedVaultKey,
    );

    expect(unwrapped).toEqual(vaultKey);
  });

  it('encrypts and decrypts a vault object', async () => {
    const vaultKey = randomBytes(32);
    const entry = {
      title: 'Correo',
      username: 'ana@example.test',
      password: 'CONTRASEÑA_DE_PRUEBA_XYZ',
    };

    const encrypted = await encryptItem(vaultKey, entry);
    await expect(decryptItem(vaultKey, encrypted.iv, encrypted.ciphertext)).resolves.toEqual(entry);
  });

  it('is deterministic only when the same IV is explicitly forced in tests', async () => {
    const vaultKey = randomBytes(32);
    const entry = { title: 'Example', password: 'secret' };
    const firstIv = new Uint8Array(12).fill(1);
    const secondIv = new Uint8Array(12).fill(2);

    const first = await encryptItem(vaultKey, entry, firstIv);
    const sameIv = await encryptItem(vaultKey, entry, firstIv);
    const differentIv = await encryptItem(vaultKey, entry, secondIv);

    expect(sameIv.ciphertext).toBe(first.ciphertext);
    expect(differentIv.ciphertext).not.toBe(first.ciphertext);
  });
});
