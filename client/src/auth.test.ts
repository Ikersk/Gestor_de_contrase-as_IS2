import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  changeMasterPassword,
  completeMfaLogin,
  getVaultKey,
  loginWithMasterPassword,
  logoutFromMemory,
  registerWithMasterPassword,
} from './auth';
import { ApiError, createVaultItem } from './api';
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

  it('rotates derived material without sending either master password', async () => {
    const masterKey = await deriveMasterKey(masterPassword, salt, DEFAULT_KDF_ITERATIONS);
    const { encryptionKey, authHash } = await deriveSubkeys(masterKey);
    const wrapped = await wrapVaultKey(encryptionKey, vaultKey, new Uint8Array(12).fill(4));
    let changeBody: Record<string, unknown> | undefined;
    vi.stubGlobal('fetch', vi.fn(async (input: string, init?: RequestInit) => {
      if (input.includes('/auth/salt')) {
        return new Response(JSON.stringify({
          kdfSalt: bytesToBase64(salt),
          kdfIterations: DEFAULT_KDF_ITERATIONS,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (input.includes('/auth/login')) {
        return new Response(JSON.stringify(wrapped), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (input.includes('/auth/change-password')) {
        changeBody = JSON.parse(String(init?.body));
        return new Response(null, { status: 204 });
      }
      return new Response(null, { status: 204 });
    }));

    await loginWithMasterPassword(email, masterPassword);
    await changeMasterPassword(masterPassword, 'new correct password');

    expect(changeBody).toMatchObject({
      currentAuthHash: authHash,
      kdfIterations: DEFAULT_KDF_ITERATIONS,
    });
    expect(changeBody).not.toHaveProperty('currentPassword');
    expect(changeBody).not.toHaveProperty('newPassword');
    expect(changeBody?.wrappedVaultKey).toEqual(expect.any(String));
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

// Login en dos pasos: la vault key no puede existir en el cliente hasta que el
// segundo factor este verificado, y un fallo no debe destruir el reto pendiente.
describe('MFA login challenge', () => {
  const masterKeyPromise = deriveMasterKey(masterPassword, salt, DEFAULT_KDF_ITERATIONS);

  /** fetch simulado: salt + login mfaRequired + verify que falla una vez. */
  function stubMfaFetch(wrapped: { wrappedVaultKey: string; wrapIv: string }) {
    const verifyBodies: Array<Record<string, unknown>> = [];
    let verifyAttempts = 0;
    vi.stubGlobal('fetch', vi.fn(async (input: string, init?: RequestInit) => {
      if (input.includes('/auth/salt')) {
        return new Response(JSON.stringify({
          kdfSalt: bytesToBase64(salt),
          kdfIterations: DEFAULT_KDF_ITERATIONS,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (input.includes('/auth/login')) {
        return new Response(JSON.stringify({ mfaRequired: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (input.includes('/auth/mfa/verify')) {
        verifyBodies.push(JSON.parse(String(init?.body)));
        verifyAttempts += 1;
        if (verifyAttempts === 1) {
          return new Response(JSON.stringify({ error: 'Invalid verification code' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response(JSON.stringify(wrapped), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(null, { status: 204 });
    }));
    return { verifyBodies };
  }

  it('holds the vault key back until the code is verified, then unwraps it', async () => {
    const { encryptionKey } = await deriveSubkeys(await masterKeyPromise);
    const wrapped = await wrapVaultKey(encryptionKey, vaultKey, new Uint8Array(12).fill(4));
    const { verifyBodies } = stubMfaFetch(wrapped);

    const outcome = await loginWithMasterPassword(email, masterPassword);
    expect(outcome).toBe('mfa-required');
    expect(getVaultKey()).toBeNull();

    // Código incorrecto: el servidor responde 401 como ApiError con su estado.
    let caught: unknown;
    try {
      await completeMfaLogin('000000');
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).status).toBe(401);
    expect(getVaultKey()).toBeNull();

    // El reto sobrevive al fallo y el segundo intento completa la sesión.
    await completeMfaLogin('123456');
    expect(getVaultKey()).toEqual(vaultKey);
    expect(verifyBodies).toEqual([{ code: '000000' }, { code: '123456' }]);

    // Al completarse, el material pendiente se descarta.
    await expect(completeMfaLogin('123456')).rejects.toThrow('ya no está disponible');
  });

  it('refuses to verify a code when there is no pending challenge', async () => {
    const { encryptionKey } = await deriveSubkeys(await masterKeyPromise);
    const wrapped = await wrapVaultKey(encryptionKey, vaultKey, new Uint8Array(12).fill(4));
    stubMfaFetch(wrapped);

    // Limpia el estado que dejó la prueba anterior antes de comprobar el reto ausente.
    await logoutFromMemory();
    await expect(completeMfaLogin('123456')).rejects.toThrow('ya no está disponible');
    expect(getVaultKey()).toBeNull();
  });

  it('clears any pending challenge when a new login starts or on logout', async () => {
    const { encryptionKey } = await deriveSubkeys(await masterKeyPromise);
    const wrapped = await wrapVaultKey(encryptionKey, vaultKey, new Uint8Array(12).fill(4));
    stubMfaFetch(wrapped);

    await loginWithMasterPassword(email, masterPassword);
    await logoutFromMemory();
    await expect(completeMfaLogin('123456')).rejects.toThrow('ya no está disponible');
  });
});