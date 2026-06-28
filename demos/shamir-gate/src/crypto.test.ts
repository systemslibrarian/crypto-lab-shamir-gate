import { describe, it, expect } from 'vitest';
import {
  secretToInt,
  intToSecret,
  generateAESKey,
  aesEncrypt,
  aesDecrypt,
  keyToInt,
  intToKey,
  toHex,
  fromHex,
  AES_KEY_PRIME,
} from './crypto';
import { generateShares, reconstructSecret } from './math';

describe('text ↔ integer encoding', () => {
  it('round-trips UTF-8 text through the field encoding', () => {
    for (const text of ['My Secret', 'hello world', 'café ☕', '1 Cor 10:31']) {
      const { value, prime } = secretToInt(text);
      expect(value).toBeLessThan(prime); // fits the chosen field
      expect(intToSecret(value)).toBe(text);
    }
  });
  it('maps the empty string to 0', () => {
    expect(secretToInt('').value).toBe(0n);
    expect(intToSecret(0n)).toBe('');
  });
});

describe('hex utilities', () => {
  it('round-trips bytes through hex', () => {
    const bytes = new Uint8Array([0, 1, 15, 16, 255, 128]);
    expect(toHex(bytes)).toBe('00010f10ff80');
    expect(Array.from(fromHex('00010f10ff80'))).toEqual(Array.from(bytes));
  });
});

describe('AES key ↔ integer (32 bytes, big-endian)', () => {
  it('round-trips a full 256-bit key', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const v = keyToInt(key);
    expect(v).toBeLessThan(AES_KEY_PRIME); // key fits below the 2^256+297 prime
    expect(Array.from(intToKey(v))).toEqual(Array.from(key));
  });
  it('pads small integers back to 32 bytes', () => {
    const k = intToKey(1n);
    expect(k).toHaveLength(32);
    expect(k[31]).toBe(1);
    expect(k[0]).toBe(0);
  });
});

describe('AES-256-GCM', () => {
  it('encrypts and decrypts a message', async () => {
    const key = await generateAESKey();
    const { ciphertext, iv } = await aesEncrypt(key, 'Top secret document');
    expect(await aesDecrypt(key, ciphertext, iv)).toBe('Top secret document');
  });

  it('fails authentication with the wrong key', async () => {
    const { ciphertext, iv } = await aesEncrypt(await generateAESKey(), 'classified');
    await expect(aesDecrypt(await generateAESKey(), ciphertext, iv)).rejects.toThrow();
  });
});

describe('end-to-end: split the AES key, then reconstruct and decrypt', () => {
  it('decrypts only after t shares are recombined', async () => {
    const message = 'launch authorized';
    const t = 3, n = 5;

    const key = await generateAESKey();
    const { ciphertext, iv } = await aesEncrypt(key, message);

    // Split the key across n custodians.
    const { shares } = await generateShares(keyToInt(key), t, n, AES_KEY_PRIME);

    // Any t custodians can rebuild the exact key and decrypt.
    const reKey = intToKey(reconstructSecret(shares.slice(0, t), AES_KEY_PRIME));
    expect(Array.from(reKey)).toEqual(Array.from(key));
    expect(await aesDecrypt(reKey, ciphertext, iv)).toBe(message);
  });
});
