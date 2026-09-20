import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_PASSWORD_CHARACTER_SELECTION,
  generateSecurePassword,
} from './password-generator';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('secure password generator', () => {
  it('uses window.crypto.getRandomValues and includes every selected set', () => {
    const getRandomValues = vi.fn((values: Uint32Array) => {
      values[0] = 0;
      return values;
    });
    vi.stubGlobal('window', { crypto: { getRandomValues } });

    const password = generateSecurePassword(16, DEFAULT_PASSWORD_CHARACTER_SELECTION);

    expect(password).toHaveLength(16);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[0-9]/);
    expect(password).toMatch(/[!@#$%^&*()[\]{}|;:,.<>?/~`\-=]/);
    expect(getRandomValues).toHaveBeenCalled();
  });

  it('rejects generation when no character set is selected', () => {
    vi.stubGlobal('window', { crypto: { getRandomValues: vi.fn() } });

    expect(() => generateSecurePassword(16, {
      uppercase: false,
      lowercase: false,
      numbers: false,
      symbols: false,
    })).toThrow('Selecciona al menos un tipo de carácter');
  });
});