import { describe, it, expect } from 'vitest';
import {
  modPow,
  modInverse,
  extGcd,
  evalPoly,
  lagrangeAt0,
  lagrangeEvalAt,
  generateShares,
  reconstructSecret,
  polyForSecret,
  randomBigInt,
  choosePrime,
} from './math';

const P = 65537n; // a prime field large enough for the tests below

/** All k-element subsets of [0, n). */
function combinations(n: number, k: number): number[][] {
  const out: number[][] = [];
  const pick = (start: number, acc: number[]) => {
    if (acc.length === k) { out.push([...acc]); return; }
    for (let i = start; i < n; i++) pick(i + 1, [...acc, i]);
  };
  pick(0, []);
  return out;
}

describe('modPow', () => {
  it('computes modular exponentiation', () => {
    expect(modPow(2n, 10n, 1000n)).toBe(24n); // 1024 mod 1000
    expect(modPow(3n, 0n, 7n)).toBe(1n);
    expect(modPow(7n, 256n, 13n)).toBe(modPow(7n, 256n % 12n, 13n)); // Fermat
  });
  it('returns 0 for modulus 1', () => {
    expect(modPow(5n, 3n, 1n)).toBe(0n);
  });
});

describe('modInverse', () => {
  it('satisfies a * a^-1 ≡ 1 (mod p)', () => {
    for (const a of [1n, 2n, 3n, 100n, 65536n]) {
      const inv = modInverse(a, P);
      expect((a * inv) % P).toBe(1n);
    }
  });
  it('throws on inverse of 0', () => {
    expect(() => modInverse(0n, P)).toThrow();
  });
  it('normalizes negative inputs', () => {
    const inv = modInverse(-3n, P);
    expect(((-3n % P + P) * inv) % P).toBe(1n);
  });
});

describe('extGcd', () => {
  it('returns gcd and Bézout coefficients a*x + b*y = gcd', () => {
    const { gcd, x, y } = extGcd(240n, 46n);
    expect(gcd).toBe(2n);
    expect(240n * x + 46n * y).toBe(gcd);
  });
});

describe('evalPoly', () => {
  it('evaluates via Horner: f(x) = 2 + 3x + 4x^2', () => {
    const c = [2n, 3n, 4n];
    expect(evalPoly(c, 0n, P)).toBe(2n);
    expect(evalPoly(c, 1n, P)).toBe(9n);
    expect(evalPoly(c, 2n, P)).toBe(24n);
  });
});

describe('lagrange interpolation', () => {
  it('recovers f(0) from points on a known polynomial', () => {
    const c = [42n, 17n, 5n]; // f(0) = 42
    const pts = [1n, 2n, 3n].map(x => ({ x, y: evalPoly(c, x, P) }));
    expect(lagrangeAt0(pts, P)).toBe(42n);
  });
  it('lagrangeEvalAt reproduces the polynomial at arbitrary x', () => {
    const c = [42n, 17n, 5n];
    const pts = [1n, 2n, 3n].map(x => ({ x, y: evalPoly(c, x, P) }));
    for (const x of [0n, 4n, 100n, 65000n]) {
      expect(lagrangeEvalAt(pts, x, P)).toBe(evalPoly(c, x, P));
    }
  });
});

describe('generateShares', () => {
  it('produces n shares at x = 1..n with f(0) = secret', async () => {
    const { shares, coefficients } = await generateShares(1234n, 3, 6, P);
    expect(shares).toHaveLength(6);
    expect(shares.map(s => s.x)).toEqual([1n, 2n, 3n, 4n, 5n, 6n]);
    expect(coefficients[0]).toBe(1234n);
    for (const s of shares) {
      expect(s.y).toBe(evalPoly(coefficients, s.x, P));
    }
  });

  it('builds a polynomial of degree exactly t-1 (leading coefficient ≠ 0)', async () => {
    for (const t of [2, 3, 4, 5]) {
      const { coefficients } = await generateShares(7n, t, t, P);
      expect(coefficients).toHaveLength(t);
      expect(coefficients[t - 1]).not.toBe(0n);
    }
  });

  it('keeps every coefficient inside the field [0, p)', async () => {
    const { coefficients } = await generateShares(99n, 4, 8, P);
    for (const c of coefficients) {
      expect(c >= 0n && c < P).toBe(true);
    }
  });

  it('rejects a secret that does not fit the field', async () => {
    await expect(generateShares(P + 1n, 2, 3, P)).rejects.toThrow();
  });
});

describe('reconstruction round-trip', () => {
  it('recovers the secret from EVERY t-subset of the n shares', async () => {
    const secret = 31337n;
    const t = 3, n = 6;
    const { shares } = await generateShares(secret, t, n, P);
    for (const subset of combinations(n, t)) {
      const picked = subset.map(i => shares[i]);
      expect(reconstructSecret(picked, P)).toBe(secret);
    }
  });

  it('also recovers from MORE than t shares', async () => {
    const secret = 500n;
    const { shares } = await generateShares(secret, 3, 6, P);
    expect(reconstructSecret(shares, P)).toBe(secret); // all 6
    expect(reconstructSecret(shares.slice(0, 4), P)).toBe(secret); // 4 of 6
  });
});

describe('the threshold theorem — t-1 shares reveal nothing', () => {
  it('for ANY candidate secret there is a polynomial consistent with t-1 shares', async () => {
    const t = 3, n = 5;
    const { shares } = await generateShares(12345n, t, n, P);
    const observed = shares.slice(0, t - 1); // attacker holds t-1 = 2 shares

    // Every possible secret in the field is equally consistent: there exists a
    // degree-(t-1) polynomial through the observed shares with f(0) = S, for any S.
    for (const candidate of [0n, 1n, 12345n, 40000n, P - 1n]) {
      const coeffs = polyForSecret(observed, candidate, P);
      expect(evalPoly(coeffs, 0n, P)).toBe(candidate); // hits the candidate secret
      for (const s of observed) {
        expect(evalPoly(coeffs, s.x, P)).toBe(s.y); // and stays consistent with shares
      }
    }
  });

  it('distinct candidates yield distinct polynomials (no information leaks)', async () => {
    const { shares } = await generateShares(777n, 3, 5, P);
    const observed = shares.slice(0, 2);
    const a = polyForSecret(observed, 100n, P);
    const b = polyForSecret(observed, 200n, P);
    expect(a).not.toEqual(b);
  });
});

describe('randomBigInt', () => {
  it('stays within [min, max) across many draws', async () => {
    for (let i = 0; i < 200; i++) {
      const v = await randomBigInt(10n, 20n);
      expect(v >= 10n && v < 20n).toBe(true);
    }
  });
});

describe('choosePrime', () => {
  it('returns a field prime strictly greater than the value', () => {
    expect(choosePrime(0n)).toBe(257n);
    expect(choosePrime(256n)).toBe(257n);
    expect(choosePrime(257n)).toBeGreaterThan(257n);
    expect(choosePrime(100000n)).toBeGreaterThan(100000n);
  });
});
