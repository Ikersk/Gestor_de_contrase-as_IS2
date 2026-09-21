import { describe, expect, it } from 'vitest';
import {
  FIELD_LIMITS,
  validateCredential,
  validateEmail,
  validateMasterPassword,
} from './validation';

// Las pruebas cubren los límites que también debe respetar el formulario visible.
describe('form validation limits', () => {
  it('requires a valid email within the protocol limit', () => {
    expect(validateEmail('not-an-email')).toBeTruthy();
    expect(validateEmail(`${'a'.repeat(FIELD_LIMITS.email)}@example.com`)).toBeTruthy();
    expect(validateEmail('user@example.com')).toBeNull();
  });

  it('limits the master password without weakening its minimum', () => {
    expect(validateMasterPassword('short')).toBeTruthy();
    expect(validateMasterPassword('a'.repeat(FIELD_LIMITS.masterPassword + 1))).toBeTruthy();
    expect(validateMasterPassword('a'.repeat(12))).toBeNull();
  });

  it('limits credential fields and only accepts HTTP URLs', () => {
    const valid = { title: 'GitHub', username: 'alice', password: 'secret', urls: ['https://github.com'] };
    expect(validateCredential(valid)).toBeNull();
    expect(validateCredential({ ...valid, title: '' })).toBeTruthy();
    expect(validateCredential({ ...valid, title: '123456' })).toBeTruthy();
    expect(validateCredential({ ...valid, username: '!!!' })).toBeTruthy();
    expect(validateCredential({ ...valid, username: 'user_123' })).toBeNull();
    expect(validateCredential({ ...valid, password: '123456!' })).toBeNull();
    expect(validateCredential({ ...valid, title: 'a'.repeat(FIELD_LIMITS.title + 1) })).toBeTruthy();
    expect(validateCredential({ ...valid, urls: ['javascript:alert(1)'] })).toBeTruthy();
    expect(validateCredential({ ...valid, urls: ['https://'] })).toBeTruthy();
    expect(validateCredential({ ...valid, urls: ['https://github.com', 'https://gitlab.com'] })).toBeNull();
    expect(validateCredential({ ...valid, urls: [] })).toBeTruthy();
    expect(validateCredential({ ...valid, urls: Array(FIELD_LIMITS.maxUrls + 1).fill('https://example.com') })).toBeTruthy();
    expect(validateCredential({ ...valid, totpSecret: 'JBSW Y3DP EHPK 3PXP' })).toBeNull();
    expect(validateCredential({ ...valid, totpSecret: 'otpauth://totp/Arca:demo?secret=JBSWY3DPEHPK3PXP' })).toBeNull();
    expect(validateCredential({ ...valid, totpSecret: 'not-valid' })).toBeTruthy();
  });
});