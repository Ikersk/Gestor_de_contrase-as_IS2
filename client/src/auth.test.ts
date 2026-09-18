import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  getVaultKey,
  loginWithMasterPassword,
  logoutFromMemory,
  registerWithMasterPassword,
} from './auth';
import { createVaultItem } from './api';
import { DEFAULT_KDF_ITERATIONS, deriveMasterKey, deriveSubkeys, bytesToBase64 } from './crypto/kdf.js';
import { wrapVaultKey } from './crypto/vault-key.js';

const email = 'ana@example.test';
const masterPassword = 'correct horse battery staple';
const salt = new Uint8Array(16).fill(8);
const vaultKey = new Uint8Array(32).fill(6);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('client authentication flow', () => {
  it('registers with derived material and never sends the master password', async () => {
    let registrationBody: Record<string, unknown> | undefined;
    vi.stubGlobal('fetch', vi.fn(async (_input: string, init?: RequestInit) => {
      registrationBody = JSON.parse(String(init?.body));
      return new Response(null, { status: 201 });
    }));

    await registerWithMasterPassword(email, masterPassword);

    expect(registrationBody).toMatchObject({
      email,
      kdfIterations: DEFAULT_KDF_ITERATIONS,
    });
    expect(registrationBody).not.toHaveProperty('masterPassword');
    expect(registrationBody).not.toHaveProperty('password');
    expect(registrationBody?.authHash).toEqual(expect.any(String));
    expect(registrationBody?.wrappedVaultKey).toEqual(expect.any(String));
    expect(registrationBody?.wrapIv).toEqual(expect.any(String));
  });

  it('recovers the vault key in memory and clears it on logout', async () => {
    const masterKey = await deriveMasterKey(masterPassword, salt, DEFAULT_KDF_ITERATIONS);
    const { encryptionKey, authHash } = await deriveSubkeys(masterKey);
    const wrapped = await wrapVaultKey(encryptionKey, vaultKey, new Uint8Array(12).fill(4));
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      if (input.includes('/auth/salt')) {
        return new Response(JSON.stringify({
          kdfSalt: bytesToBase64(salt),
          kdfIterations: DEFAULT_KDF_ITERATIONS,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (input.includes('/auth/login')) {
        const body = JSON.parse(String(init?.body));
        expect(body).toEqual({ email, authHash });
        return new Response(JSON.stringify(wrapped), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(null, { status: 204 });
    });
    vi.stubGlobal('fetch', fetchMock);

    await loginWithMasterPassword(email, masterPassword);
    expect(getVaultKey()).toEqual(vaultKey);

    await logoutFromMemory();
    expect(getVaultKey()).toBeNull();
  });
});

describe('vault API response handling', () => {
  it('reads the id from a JSON 201 response', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ id: 42 }),
      { status: 201, headers: { 'Content-Type': 'application/json' } },
    )));

    await expect(createVaultItem({ iv: 'iv', ciphertext: 'ciphertext' })).resolves.toEqual({ id: 42 });
  });
});