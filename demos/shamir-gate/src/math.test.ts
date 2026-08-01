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

  // NOTE: this replaces an assertion that `coefficients[t - 1] !== 0n` — "degree
  // exactly t-1". That assertion was the bug, not a guarantee. Restricting the
  // leading coefficient to [1, p) makes exactly one candidate secret unreachable
  // from any given set of t-1 shares, so a sub-threshold holder can rule it out
  // and the Security Proof tab's claim is false by 1/p. The polynomial has t
  // coefficients and degree AT MOST t-1; every non-constant one is uniform over
  // the full field.
  it('builds a polynomial with t coefficients and the secret at f(0)', async () => {
    for (const t of [2, 3, 4, 5]) {
      const { coefficients } = await generateShares(7n, t, t, P);
      expect(coefficients).toHaveLength(t);
      expect(coefficients[0]).toBe(7n);
      expect(evalPoly(coefficients, 0n, P)).toBe(7n);
    }
  });

  it('draws the LEADING coefficient uniformly over [0, p), 0 included', async () => {
    // Over a small field, 0 must turn up for the leading coefficient at roughly
    // the uniform rate. With p = 257 and 6000 draws the expected count is ~23, so
    // seeing none has probability ~e^-23: a rejection-sampling regression fails
    // this essentially every run.
    const p = 257n;
    const DRAWS = 6000;
    let zeroLeading = 0;
    const seen = new Set<bigint>();
    for (let i = 0; i < DRAWS; i++) {
      const { coefficients } = await generateShares(42n, 3, 3, p);
      seen.add(coefficients[2]);
      if (coefficients[2] === 0n) zeroLeading++;
    }
    expect(zeroLeading).toBeGreaterThan(0);
    // ...and the draw covers essentially the whole field, not a punctured subset.
    expect(seen.size).toBeGreaterThanOrEqual(250);
  });

  it('leaves a single share consistent with EVERY secret in the field (t = 2)', async () => {
    // At t = 2 the sole non-constant coefficient IS the leading one, so this is
    // where a leading-coefficient restriction bites hardest. One share is t-1
    // shares; interpolating it alone gives f(0) = y, so the set of y values a
    // fixed secret can produce must cover the whole field. If it did not, a
    // single-share holder could rule the missing candidate out.
    const p = 257n;
    const SECRET = 42n;
    const seen = new Set<bigint>();
    for (let i = 0; i < 6000; i++) {
      const { shares } = await generateShares(SECRET, 2, 3, p);
      seen.add(shares[0].y);
    }
    expect(seen.size).toBeGreaterThanOrEqual(250);
    // The true secret itself must be among the reachable values — that is the
    // candidate the old code excluded (y = secret happens iff a_1 = 0).
    expect(seen.has(SECRET)).toBe(true);
  });

  it('can produce the degenerate fit the Security Proof tab relies on', async () => {
    // The Security Proof tab claims all 257 secrets are consistent with the fixed
    // shares (1,75) and (2,140) over p = 257. S = 10 is the one whose fitting
    // polynomial has a zero leading coefficient: f(x) = 10 + 65x, degree 1.
    const p = 257n;
    const fitted = polyForSecret([{ x: 1n, y: 75n }, { x: 2n, y: 140n }], 10n, p);
    expect(evalPoly(fitted, 0n, p)).toBe(10n);
    expect(evalPoly(fitted, 1n, p)).toBe(75n);
    expect(evalPoly(fitted, 2n, p)).toBe(140n);
    expect(fitted[2]).toBe(0n); // degree drops to 1 for exactly this candidate

    // generateShares must be able to emit polynomials of that shape for S = 10,
    // otherwise the tab's "every possible secret" statement is false of this
    // implementation.
    let sawDegenerate = false;
    for (let i = 0; i < 6000 && !sawDegenerate; i++) {
      const { coefficients } = await generateShares(10n, 3, 3, p);
      if (coefficients[2] === 0n) sawDegenerate = true;
    }
    expect(sawDegenerate).toBe(true);
  });

  it('still reconstructs correctly when the leading coefficient is 0', async () => {
    // Degree drop must not break correctness: t points determine a unique
    // polynomial of degree <= t-1 either way.
    const p = 257n;
    let checked = 0;
    for (let i = 0; i < 6000 && checked < 5; i++) {
      const { shares, coefficients } = await generateShares(99n, 3, 5, p);
      if (coefficients[2] !== 0n) continue;
      checked++;
      expect(reconstructSecret(shares.slice(0, 3), p)).toBe(99n);
      expect(reconstructSecret(shares.slice(2, 5), p)).toBe(99n);
    }
    expect(checked).toBeGreaterThan(0);
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
