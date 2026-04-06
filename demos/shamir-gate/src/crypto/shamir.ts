/**
 * Shamir's Secret Sharing (SSS)
 * 
 * How to Share a Secret — Adi Shamir (1979)
 * CACM, Vol. 22, No. 11, pp. 612-613
 * 
 * Implements threshold secret sharing:
 * - k-of-n threshold: any k shares can reconstruct the secret
 * - k-1 shares: the secret is information-theoretically hidden
 * - Perfect secrecy: with k-1 shares, all 256 possible secrets are equally likely
 * 
 * All arithmetic over GF(2⁸) for byte-level splitting
 */

import {
  createPolynomial,
  evaluateAt,
  generateShares as generateSharesFromPoly,
  lagrangeInterpolate,
  Share,
  Polynomial
} from './polynomial';

/**
 * Configuration for Shamir's Secret Sharing
 */
export interface ShamirConfig {
  /** Threshold: minimum shares needed to reconstruct */
  k: number;
  /** Total number of shares generated */
  n: number;
}

/**
 * Validate configuration
 */
function validateConfig(config: ShamirConfig): void {
  if (config.k < 2) throw new Error('k must be at least 2');
  if (config.n < config.k) throw new Error('n must be >= k');
  if (config.n > 255) throw new Error('n must be <= 255 (0 is reserved for x=0, the secret)');
}

/**
 * Split a single byte into n shares with k-of-n threshold
 * 
 * Algorithm:
 * 1. Create polynomial f of degree k-1 with f(0) = secret
 * 2. Evaluate at x = 1, 2, ..., n to get shares
 * 3. Return (i, f(i)) pairs
 * 
 * @param secret Byte value (0-255) to split
 * @param config {k, n} threshold configuration
 * @returns Array of n shares, each with (x, y, index)
 */
export function split(secret: number, config: ShamirConfig): Share[] {
  validateConfig(config);

  secret &= 0xff;

  // Create polynomial of degree k-1 with f(0) = secret
  const poly = createPolynomial(secret, config.k - 1);

  // Generate shares (1, f(1)), (2, f(2)), ..., (n, f(n))
  return generateSharesFromPoly(poly, config.n);
}

/**
 * Reconstruct a single byte from k shares
 * 
 * Algorithm:
 * 1. Use Lagrange interpolation: f(x) = Σ yᵢ · Lᵢ(x)
 * 2. Evaluate at x=0: f(0) = Σ yᵢ · Lᵢ(0) = secret
 * 
 * With fewer than k shares: returns garbage (polynomial is underdetermined)
 * With k or more shares: returns the unique secret (if shares are on same polynomial)
 * 
 * @param shares Array of k shares (need exactly k for security proof)
 * @returns Reconstructed secret byte
 */
export function reconstruct(shares: Share[]): number {
  if (shares.length === 0) {
    throw new Error('Cannot reconstruct with zero shares');
  }

  // Use Lagrange interpolation to evaluate polynomial at x=0
  return lagrangeInterpolate(shares, 0);
}

/**
 * Share representation for multi-byte secrets
 * 
 * Format: shamir-gate-v1:{k}:{n}:{index}:{hex_y_values}
 * Example: shamir-gate-v1:3:5:2:a4f2c8d1e5b2f9a3c7...
 */
export interface ShareSet {
  /** Threshold: needed to reconstruct */
  k: number;
  /** Total shares generated */
  n: number;
  /** Share index (1-based) */
  index: number;
  /** y-values for each byte, encoded as hex */
  yValues: Uint8Array;
}

/**
 * Serialize a share set to string format
 */
export function serializeShare(share: ShareSet): string {
  const yHex = Array.from(share.yValues)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return `shamir-gate-v1:${share.k}:${share.n}:${share.index}:${yHex}`;
}

/**
 * Deserialize a share set from string format
 */
export function deserializeShare(shareStr: string): ShareSet {
  const match = shareStr.match(/^shamir-gate-v1:(\d+):(\d+):(\d+):(.+)$/);

  if (!match) {
    throw new Error('Invalid share format');
  }

  const [, kStr, nStr, indexStr, yHex] = match;
  const k = parseInt(kStr, 10);
  const n = parseInt(nStr, 10);
  const index = parseInt(indexStr, 10);

  // Validate parameters
  if (k < 2 || n < k || n > 255 || index < 1 || index > n) {
    throw new Error('Invalid share parameters');
  }

  // Parse hex y-values (2 chars per byte)
  if (yHex.length % 2 !== 0) {
    throw new Error('Invalid hex encoding in share');
  }

  const yValues = new Uint8Array(yHex.length / 2);
  for (let i = 0; i < yValues.length; i++) {
    const hex = yHex.substring(i * 2, i * 2 + 2);
    yValues[i] = parseInt(hex, 16);

    if (isNaN(yValues[i])) {
      throw new Error('Invalid hex value in share');
    }
  }

  return { k, n, index, yValues };
}

/**
 * Split a multi-byte secret into n share sets
 * 
 * Each byte is split independently over GF(2⁸) using same polynomial degree
 * but different random coefficients (except the constant term, which is the secret byte)
 * 
 * @param secret Multi-byte secret to split
 * @param config {k, n} threshold configuration
 * @returns Array of n ShareSet objects (one per share holder)
 */
export function splitSecret(secret: Uint8Array, config: ShamirConfig): ShareSet[] {
  validateConfig(config);

  // Allocate n share sets
  const shareSets: ShareSet[] = [];
  for (let i = 1; i <= config.n; i++) {
    shareSets.push({
      k: config.k,
      n: config.n,
      index: i,
      yValues: new Uint8Array(secret.length)
    });
  }

  // Split each byte independently
  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    const byteShares = split(secret[byteIdx], config);

    // Distribute y-values to each share set
    for (const share of byteShares) {
      shareSets[share.index - 1].yValues[byteIdx] = share.y;
    }
  }

  return shareSets;
}

/**
 * Reconstruct multi-byte secret from k share sets
 * 
 * @param shareSets Array of k ShareSet objects
 * @param k Threshold (number of shares needed)
 * @returns Reconstructed multi-byte secret
 */
export function reconstructSecret(shareSets: ShareSet[], k: number): Uint8Array {
  if (shareSets.length < k) {
    throw new Error(`Need at least ${k} shares to reconstruct, got ${shareSets.length}`);
  }

  // Validate that all share sets have the same parameters
  const firstShare = shareSets[0];
  for (const share of shareSets.slice(1)) {
    if (
      share.k !== firstShare.k ||
      share.n !== firstShare.n ||
      share.yValues.length !== firstShare.yValues.length
    ) {
      throw new Error('Share sets have mismatched parameters');
    }
  }

  const secretLength = firstShare.yValues.length;
  const secret = new Uint8Array(secretLength);

  // Reconstruct each byte independently
  for (let byteIdx = 0; byteIdx < secretLength; byteIdx++) {
    // Create Share objects for this byte from all share sets
    const byteShares: Share[] = shareSets.map(share => ({
      x: share.index,
      y: share.yValues[byteIdx],
      index: share.index
    }));

    // Take first k shares and reconstruct (all share sets should give same result)
    secret[byteIdx] = reconstruct(byteShares.slice(0, k));
  }

  return secret;
}

/**
 * Test vector verification
 */
export function verifyShamir(): boolean {
  const config: ShamirConfig = { k: 2, n: 3 };

  // Test 1: Single byte split and reconstruct
  const shares1 = split(42, config);
  const recovered1 = reconstruct(shares1.slice(0, 2));
  if (recovered1 !== 42) return false;

  // Test 2: Multi-byte split and reconstruct
  const secret = new Uint8Array([73, 42, 255, 1]);
  const shareSets = splitSecret(secret, config);
  const recovered2 = reconstructSecret(shareSets, 2);

  for (let i = 0; i < secret.length; i++) {
    if (secret[i] !== recovered2[i]) return false;
  }

  // Test 3: Share serialization
  const serialized = serializeShare(shareSets[0]);
  const deserialized = deserializeShare(serialized);

  if (
    deserialized.k !== shareSets[0].k ||
    deserialized.n !== shareSets[0].n ||
    deserialized.index !== shareSets[0].index
  ) {
    return false;
  }

  for (let i = 0; i < secret.length; i++) {
    if (deserialized.yValues[i] !== shareSets[0].yValues[i]) return false;
  }

  return true;
}
