import { describe, it, expect } from 'vitest';
import { gfAdd, gfSub, gfMul, gfDiv, gfInv, gfPow, verifyGF256 } from '../crypto/gf256';
import { createPolynomial, evaluateAt, lagrangeInterpolate, verifyPolynomial } from '../crypto/polynomial';
import { split, reconstruct, splitSecret, reconstructSecret, serializeShare, deserializeShare, verifyShamir } from '../crypto/shamir';
import { findAllConsistentSecrets, verifySecurityProof } from '../crypto/security-proof';

describe('GF(2⁸) Arithmetic', () => {
  it('should add correctly (XOR)', () => {
    expect(gfAdd(0x53, 0xca)).toBe(0x99);
    expect(gfAdd(5, 3)).toBe(6); // 5 XOR 3 = 6
    expect(gfAdd(255, 255)).toBe(0); // All ones XOR all ones = 0
  });

  it('should subtract correctly (same as add in GF(2⁸))', () => {
    expect(gfSub(0x99, 0xca)).toBe(0x53); // inverse of add
    expect(gfSub(6, 3)).toBe(5); // 6 XOR 3 = 5
  });

  it('should multiply correctly', () => {
    // Known test vector: gfMul(3, 7) = 9
    expect(gfMul(3, 7)).toBe(9);

    // AES test vector
    expect(gfMul(0x53, 0xca)).toBe(0x01);

    // Multiplication by 0 and 1
    expect(gfMul(0, 42)).toBe(0);
    expect(gfMul(1, 42)).toBe(42);
  });

  it('should compute multiplicative inverse correctly', () => {
    // inv(0x53) = 0xca
    expect(gfInv(0x53)).toBe(0xca);

    // a * inv(a) = 1 for all a ≠ 0
    for (let i = 1; i < 256; i++) {
      expect(gfMul(i, gfInv(i))).toBe(1);
    }
  });

  it('should divide correctly', () => {
    // a / b = a * inv(b)
    expect(gfDiv(0x01, 0x53)).toBe(0xca);

    // (a * b) / b = a
    for (let i = 1; i < 256; i++) {
      for (let j = 1; j < 256; j++) {
        const product = gfMul(i, j);
        const quotient = gfDiv(product, j);
        expect(quotient).toBe(i);
      }
    }
  });

  it('should compute powers correctly', () => {
    // a^1 = a
    expect(gfPow(42, 1)).toBe(42);

    // a^0 = 1 (except 0^0 = 1)
    expect(gfPow(42, 0)).toBe(1);

    // 0^n = 0 for n > 0
    expect(gfPow(0, 5)).toBe(0);

    // a^255 = 1 for all a ≠ 0 (Fermat's little theorem in GF(2⁸))
    for (let i = 1; i < 256; i++) {
      expect(gfPow(i, 255)).toBe(1);
    }
  });

  it('should pass built-in verification', () => {
    expect(verifyGF256()).toBe(true);
  });
});

describe('Polynomial Arithmetic', () => {
  it('should create polynomial with correct secret', () => {
    const poly = createPolynomial(73, 2);
    expect(poly.coefficients[0]).toBe(73);
    expect(poly.degree).toBe(2);
  });

  it('should evaluate polynomial using Horner method', () => {
    const poly = createPolynomial(10, 1);
    poly.coefficients[1] = 5;

    // f(x) = 10 + 5x
    expect(evaluateAt(poly, 0)).toBe(10);
    expect(evaluateAt(poly, 1)).toBe(gfAdd(10, 5)); // 10 + 5 = 15 (in GF(2⁸))
  });

  it('should use Lagrange interpolation to recover secret', () => {
    const poly = createPolynomial(42, 1);
    const coeffA = poly.coefficients[1];

    // Create shares: (1, f(1)), (2, f(2))
    const y1 = evaluateAt(poly, 1);
    const y2 = evaluateAt(poly, 2);

    const shares = [
      { x: 1, y: y1, index: 1 },
      { x: 2, y: y2, index: 2 }
    ];

    // Interpolate at x=0 to recover secret
    const recovered = lagrangeInterpolate(shares, 0);
    expect(recovered).toBe(42);
  });

  it('should pass polynomial verification', () => {
    expect(verifyPolynomial()).toBe(true);
  });
});

describe('Shamir Secret Sharing', () => {
  it('should split and reconstruct single byte', () => {
    const shares = split(73, { k: 2, n: 3 });

    expect(shares.length).toBe(3);
    expect(shares[0].x).toBe(1);
    expect(shares[1].x).toBe(2);
    expect(shares[2].x).toBe(3);

    // Any k=2 shares should reconstruct to 73
    expect(reconstruct(shares.slice(0, 2))).toBe(73);
    expect(reconstruct(shares.slice(1, 3))).toBe(73);
    expect(reconstruct([shares[0], shares[2]])).toBe(73);
  });

  it('should handle threshold boundary (k-1 shares fail)', () => {
    const shares = split(42, { k: 3, n: 5 });

    // With k-1=2 shares, reconstruction is wrong (polynomial underdetermined)
    const recovered1 = reconstruct(shares.slice(0, 2));
    expect(recovered1).not.toBe(42);

    // With k=3 shares, reconstruction is correct
    const recovered2 = reconstruct(shares.slice(0, 3));
    expect(recovered2).toBe(42);
  });

  it('should split and reconstruct multi-byte secrets', () => {
    const secret = new Uint8Array([73, 42, 255, 0, 1]);
    const shareSets = splitSecret(secret, { k: 2, n: 3 });

    expect(shareSets.length).toBe(3);
    expect(shareSets[0].yValues.length).toBe(5);

    // Reconstruct from any k=2 shares
    const recovered1 = reconstructSecret(shareSets.slice(0, 2), 2);
    expect(recovered1).toEqual(secret);

    const recovered2 = reconstructSecret([shareSets[0], shareSets[2]], 2);
    expect(recovered2).toEqual(secret);
  });

  it('should serialize and deserialize shares', () => {
    const secret = new Uint8Array([73, 42]);
    const shareSets = splitSecret(secret, { k: 2, n: 3 });

    const serialized = serializeShare(shareSets[0]);
    expect(serialized).toMatch(/^shamir-gate-v1:\d+:\d+:\d+:[0-9a-f]+$/);

    const deserialized = deserializeShare(serialized);
    expect(deserialized.k).toBe(2);
    expect(deserialized.n).toBe(3);
    expect(deserialized.index).toBe(1);
    expect(deserialized.yValues).toEqual(shareSets[0].yValues);
  });

  it('should reject invalid share formats', () => {
    expect(() => deserializeShare('invalid')).toThrow();
    expect(() => deserializeShare('shamir-gate-v1:0:3:1:abcd')).toThrow();
    expect(() => deserializeShare('shamir-gate-v1:3:3:1:abcg')).toThrow();
  });

  it('should pass built-in verification', () => {
    expect(verifyShamir()).toBe(true);
  });
});

describe('Security Proof', () => {
  it('should prove information-theoretic security', () => {
    // With k-1 shares, all 256 secrets should be consistent
    const shares = split(999 % 256, { k: 3, n: 5 });

    // Take k-1 = 2 shares
    const consistentSecrets = findAllConsistentSecrets(shares.slice(0, 2), 3);

    // All 256 possible secrets should be consistent with k-1 shares
    expect(consistentSecrets.length).toBe(256);
    expect(new Set(consistentSecrets).size).toBe(256); // All unique
  });

  it('should verify security proof', () => {
    expect(verifySecurityProof()).toBe(true);
  });
});

describe('Round-trip Integration Tests', () => {
  it('should handle 32-byte AES key splitting', () => {
    // Generate a random 32-byte secret (simulating AES-256 key)
    const secret = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      secret[i] = Math.floor(Math.random() * 256);
    }

    const config = { k: 3, n: 5 };
    const shareSets = splitSecret(secret, config);

    // Reconstruct from k shares
    for (let variation = 0; variation < 10; variation++) {
      // Try different combinations of k shares
      const indices = new Set<number>();
      while (indices.size < config.k) {
        indices.add(Math.floor(Math.random() * config.n));
      }

      const selectedShares = Array.from(indices).map((i) => shareSets[i]);
      const recovered = reconstructSecret(selectedShares, config.k);

      expect(recovered).toEqual(secret);
    }
  });

  it('should maintain security across multiple trials', () => {
    // Split the same secret multiple times, verify consistency
    const secret = 42;

    for (let trial = 0; trial < 5; trial++) {
      const shares = split(secret, { k: 2, n: 3 });
      expect(reconstruct(shares.slice(0, 2))).toBe(42);
    }
  });
});
