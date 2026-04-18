/**
 * AES-256-GCM + secret conversion utilities for Shamir's Secret Sharing Demo
 *
 * All randomness via crypto.getRandomValues.
 * All randomness via crypto.getRandomValues only. No floating point in math layers.
 */

import { choosePrime } from './math';

/**
 * Convert a text secret to a BigInt for use in Shamir.
 * Encoding: UTF-8 bytes → big-endian integer.
 * Chooses appropriate prime automatically.
 */
export function secretToInt(text: string): { value: bigint; prime: bigint } {
  const bytes = new TextEncoder().encode(text);
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) | BigInt(b);
  }
  // prime must be > value AND > n (shares), pick conservatively
  const prime = choosePrime(value);
  return { value, prime };
}

/**
 * Convert a reconstructed BigInt back to the original text.
 */
export function intToSecret(value: bigint): string {
  if (value === 0n) return '';
  const bytes: number[] = [];
  let v = value;
  while (v > 0n) {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

/**
 * Generate a random 256-bit AES key for the "encrypt with split key" exhibit.
 * Returns raw 32-byte Uint8Array.
 */
export async function generateAESKey(): Promise<Uint8Array> {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

/**
 * Encrypt a message with AES-256-GCM.
 * Returns { ciphertext, iv } as hex strings.
 */
export async function aesEncrypt(
  key: Uint8Array,
  message: string
): Promise<{ ciphertext: string; iv: string }> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(message);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encoded);
  return {
    ciphertext: toHex(new Uint8Array(encrypted)),
    iv: toHex(iv),
  };
}

/**
 * Decrypt a message with AES-256-GCM.
 */
export async function aesDecrypt(
  key: Uint8Array,
  ciphertext: string,
  iv: string
): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromHex(iv) },
    cryptoKey,
    fromHex(ciphertext)
  );
  return new TextDecoder().decode(decrypted);
}

/**
 * Convert a 256-bit AES key (32 bytes) to a BigInt for Shamir splitting.
 * The prime must be > 2^256.
 * Uses p = 2^256 + 297 (a known prime just above 2^256).
 */
export const AES_KEY_PRIME =
  115792089237316195423570985008687907853269984665640564039457584007913129640233n;

export function keyToInt(key: Uint8Array): bigint {
  let v = 0n;
  for (const b of key) {
    v = (v << 8n) | BigInt(b);
  }
  return v;
}

export function intToKey(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// Hex utilities
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function fromHex(hex: string): Uint8Array {
  const matches = hex.match(/.{1,2}/g);
  if (!matches) return new Uint8Array(0);
  return new Uint8Array(matches.map(b => parseInt(b, 16)));
}
