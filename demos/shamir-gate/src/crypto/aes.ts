/**
 * AES-256-GCM Encryption/Decryption using Web Crypto API
 * 
 * Shamir SSS typically protects encryption keys, not data directly.
 * This module demonstrates the canonical production pattern:
 * 1. Generate random AES-256 key
 * 2. Encrypt message with AES-256-GCM
 * 3. Split the key using Shamir SSS
 * 4. Share the encrypted message + key shares with recipients
 * 5. Reconstruct the key from k shares
 * 6. Decrypt the message
 */

/**
 * Generate a random AES-256 key using Web Crypto API
 */
export async function generateAESKey(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Export AES key to raw bytes for Shamir SSS splitting
 */
export async function exportKey(key: CryptoKey): Promise<Uint8Array> {
  const exported = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(exported);
}

/**
 * Import AES key from raw bytes (reconstructed from Shamir shares)
 */
export async function importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt'
  ]);
}

/**
 * Encrypt plaintext with AES-256-GCM
 * Returns: { ciphertext: base64, iv: hex }
 */
export async function encryptAES(key: CryptoKey, plaintext: string): Promise<{ ciphertext: string; iv: string }> {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);

  // Generate random 12-byte IV (initialization vector / nonce)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt
  const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);

  // Encode to base64 and hex
  const ciphertext = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(encryptedData))));
  const ivHex = Array.from(iv).map((b) => b.toString(16).padStart(2, '0')).join('');

  return { ciphertext, iv: ivHex };
}

/**
 * Decrypt ciphertext with AES-256-GCM
 */
export async function decryptAES(key: CryptoKey, ciphertext: string, ivHex: string): Promise<string> {
  // Decode from base64 and hex
  const encryptedData = new Uint8Array(atob(ciphertext).split('').map((c) => c.charCodeAt(0)));
  const iv = new Uint8Array(ivHex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));

  // Decrypt
  const decryptedData = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encryptedData);

  // Decode to string
  const decoder = new TextDecoder();
  return decoder.decode(decryptedData);
}

/**
 * Generate key fingerprint (first 16 hex chars of SHA-256 hash)
 */
export async function getKeyFingerprint(keyBytes: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytes);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return hashHex.substring(0, 16);
}
