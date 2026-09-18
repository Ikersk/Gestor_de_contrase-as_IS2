import { describe, expect, it } from 'vitest';
import { encryptBytes } from './cipher.js';
import { deriveMasterKey } from './kdf.js';

function hexToBytes(value) {
  return Uint8Array.from(value.match(/.{2}/g).map((byte) => Number.parseInt(byte, 16)));
}

function bytesToHex(value) {
  return [...new Uint8Array(value)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

describe('known cryptographic vectors', () => {
  it('matches the PBKDF2-HMAC-SHA256 reference output', async () => {
    const derived = await deriveMasterKey('password', new Uint8Array(16), 1);

    expect(bytesToHex(derived)).toBe(
      '1fefe125ab13dd2c06db86711ec448e9490e6c73024d7d8d659126c6f9fadd68',
    );
  });

  it('matches the AES-256-GCM reference ciphertext and tag', async () => {
    const encrypted = await encryptBytes(
      new Uint8Array(32),
      new Uint8Array(16),
      new Uint8Array(12),
    );

    expect(bytesToHex(encrypted).slice(0, 32)).toBe('cea7403d4d606b6e074ec5d3baf39d18');
    expect(bytesToHex(encrypted).slice(32)).toBe('d0d1c8a799996bf0265b98b5d48ab919');
    expect(hexToBytes(bytesToHex(encrypted))).toHaveLength(32);
  });
});