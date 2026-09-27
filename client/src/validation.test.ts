import { describe, expect, it } from 'vitest';
import {
  FIELD_LIMITS,
  evaluatePasswordProtocol,
  validateCredential,
  validateEmail,
  validateMasterPassword,
  validateSecurePassword,
  validateMfaCode,
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

  it('evaluates password protocol and entropy accurately in real time', () => {
    // Caso vacío
    const emptyResult = evaluatePasswordProtocol('', 12);
    expect(emptyResult.isValid).toBe(false);
    expect(emptyResult.hasMinLength).toBe(false);
    expect(emptyResult.hasLower).toBe(false);
    expect(emptyResult.hasUpper).toBe(false);
    expect(emptyResult.hasNumber).toBe(false);
    expect(emptyResult.hasSpecial).toBe(false);
    expect(emptyResult.entropy).toBe(0);
    expect(emptyResult.level).toBe('muy-debil');

    // Caso solo minúsculas (incompleto)
    const lowerOnly = evaluatePasswordProtocol('solominusculas', 12);
    expect(lowerOnly.isValid).toBe(false);
    expect(lowerOnly.hasLower).toBe(true);
    expect(lowerOnly.hasUpper).toBe(false);
    expect(lowerOnly.hasNumber).toBe(false);
    expect(lowerOnly.hasSpecial).toBe(false);
    expect(lowerOnly.errors.length).toBeGreaterThan(0);

    // Caso que cumple todo el protocolo de Arca (minúscula, mayúscula, número, especial, >=12 caracteres)
    const strongPass = evaluatePasswordProtocol('Arca$Segura2026!', 12);
    expect(strongPass.isValid).toBe(true);
    expect(strongPass.hasMinLength).toBe(true);
    expect(strongPass.hasLower).toBe(true);
    expect(strongPass.hasUpper).toBe(true);
    expect(strongPass.hasNumber).toBe(true);
    expect(strongPass.hasSpecial).toBe(true);
    expect(strongPass.entropy).toBeGreaterThanOrEqual(75);
    expect(['fuerte', 'excelente']).toContain(strongPass.level);
    expect(strongPass.errors).toHaveLength(0);

    // Caso credencial de bóveda (mínimo 8 caracteres)
    const vaultPass = evaluatePasswordProtocol('P@ssw0rd99', 8);
    expect(vaultPass.isValid).toBe(true);
    expect(vaultPass.hasMinLength).toBe(true);
  });

  it('validates secure passwords and provides descriptive error messages', () => {
    expect(validateSecurePassword('')).toBeTruthy();
    expect(validateSecurePassword('solo_letras_largas_aqui', 12)).toContain('protocolo de seguridad');
    expect(validateSecurePassword('Arca#MasterKey99!', 12)).toBeNull();
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

// El campo MFA acepta tanto el código TOTP del authenticator como un backup code.
describe('MFA code validation', () => {
  it('accepts 6-digit TOTP codes and formatted backup codes only', () => {
    expect(validateMfaCode('')).toBeTruthy();
    expect(validateMfaCode('12345')).toBeTruthy();
    expect(validateMfaCode('abcdef')).toBeTruthy();
    expect(validateMfaCode('123456')).toBeNull();
    expect(validateMfaCode('1234567')).toBeTruthy();
    expect(validateMfaCode('abcdefgh')).toBeNull();
    expect(validateMfaCode('ABCD-EFGH')).toBeNull();
    expect(validateMfaCode('abcd-efgh')).toBeNull();
    expect(validateMfaCode('ABC2-7FGH')).toBeNull();
    expect(validateMfaCode('ABCD-EFG')).toBeTruthy();
  });
});