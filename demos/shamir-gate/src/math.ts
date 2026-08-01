/**
 * GF(p) Arithmetic for Shamir's Secret Sharing
 *
 * All arithmetic uses BigInt. No floating point.
 * All randomness uses crypto.getRandomValues.
 */

/**
 * Modular exponentiation: base^exp mod m
 * Uses square-and-multiply. All BigInt.
 */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m === 1n) return 0n;
  let result = 1n;
  base = ((base % m) + m) % m;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % m;
    }
    exp = exp / 2n;
    base = (base * base) % m;
  }
  return result;
}

/**
 * Modular inverse: a^(-1) mod p using Fermat's little theorem.
 * Requires p to be prime.
 * Returns a^(p-2) mod p.
 */
export function modInverse(a: bigint, p: bigint): bigint {
  a = ((a % p) + p) % p;
  if (a === 0n) throw new Error('modInverse of 0');
  return modPow(a, p - 2n, p);
}

/**
 * Extended Euclidean Algorithm.
 * Returns { gcd, x, y } such that a*x + b*y = gcd.
 */
export function extGcd(a: bigint, b: bigint): { gcd: bigint; x: bigint; y: bigint } {
  if (b === 0n) return { gcd: a, x: 1n, y: 0n };
  const { gcd, x: x1, y: y1 } = extGcd(b, a % b);
  return { gcd, x: y1, y: x1 - (a / b) * y1 };
}

/**
 * Generate a cryptographically random bigint in [min, max).
 * Uses crypto.getRandomValues. Rejection sampling for uniformity.
 */
export async function randomBigInt(min: bigint, max: bigint): Promise<bigint> {
  const range = max - min;
  // Number of bytes needed
  const byteLen = Math.ceil(range.toString(16).length / 2);
  const mask = (1n << BigInt(byteLen * 8)) - 1n;
  while (true) {
    const buf = new Uint8Array(byteLen);
    crypto.getRandomValues(buf);
    let val = 0n;
    for (const b of buf) {
      val = (val << 8n) | BigInt(b);
    }
    val = val & mask;
    if (val < range) {
      return val + min;
    }
  }
}

/**
 * Well-known primes that define the finite field GF(p) used for demos.
 *
 * These are ordinary primes, not "safe primes" in the p = 2q + 1 sense (none of
 * them satisfy it). Shamir secret sharing over GF(p) does not need one: it needs
 * only a prime modulus larger than the secret and larger than the number of
 * shares, so every non-zero element is invertible and Lagrange interpolation is
 * exact. Safe primes matter for discrete-log groups (Diffie-Hellman, ElGamal),
 * where a large prime-order subgroup resists small-subgroup attacks — that is a
 * different setting from this one.
 *
 * choosePrime returns the smallest prime in the list that is > minValue.
 */
const FIELD_PRIMES: bigint[] = [
  257n,
  509n,
  1021n,
  65537n,
  2147483647n, // 2^31 - 1 (Mersenne prime)
  // 2^61 - 1
  2305843009213693951n,
  // 2^127 - 1
  170141183460469231731687303715884105727n,
  // 2^256 + 297 (prime just above 2^256, used for AES keys)
  115792089237316195423570985008687907853269984665640564039457584007913129640233n,
];

export function choosePrime(minValue: bigint): bigint {
  for (const p of FIELD_PRIMES) {
    if (p > minValue) return p;
  }
  throw new Error(`No suitable prime found for value > ${minValue}`);
}

/**
 * Evaluate polynomial f(x) = coeffs[0] + coeffs[1]*x + ... mod p
 * coeffs[0] IS the secret (f(0) = secret).
 * Uses Horner's method.
 */
export function evalPoly(coeffs: bigint[], x: bigint, p: bigint): bigint {
  let result = 0n;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = (result * x + coeffs[i]) % p;
  }
  return result;
}

/**
 * Lagrange interpolation at x=0.
 * Given shares = [{x, y}], recover f(0) mod p.
 * Uses modular inverse for division. All BigInt arithmetic.
 */
export function lagrangeAt0(shares: Array<{ x: bigint; y: bigint }>, p: bigint): bigint {
  let secret = 0n;
  const k = shares.length;
  for (let i = 0; i < k; i++) {
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < k; j++) {
      if (i === j) continue;
      // (0 - x_j) / (x_i - x_j)
      num = (num * ((0n - shares[j].x + p) % p)) % p;
      den = (den * ((shares[i].x - shares[j].x + p) % p)) % p;
    }
    const li = (num * modInverse(den, p)) % p;
    secret = (secret + shares[i].y * li) % p;
  }
  return secret;
}

/**
 * Generate Shamir shares.
 * secret: bigint (the value to share)
 * t: threshold (minimum shares to reconstruct)
 * n: total shares
 * p: prime modulus (p > secret, p > n)
 * Returns array of n shares {x: 1..n, y: f(x) mod p}
 * and the polynomial coefficients (for visualization only).
 *
 * The polynomial has degree AT MOST t-1, not necessarily exactly t-1 — see the
 * comment on the coefficient draw below for why that is required, not tolerated.
 */
export async function generateShares(
  secret: bigint,
  t: number,
  n: number,
  p: bigint
): Promise<{
  shares: Array<{ x: bigint; y: bigint }>;
  coefficients: bigint[];
}> {
  if (secret >= p) throw new Error('secret must be < p');
  if (n >= p) throw new Error('n must be < p');

  // coefficients: [secret, random a1, ..., random a_{t-1}]
  //
  // EVERY non-constant coefficient — the leading one a_{t-1} included — is drawn
  // uniformly from the FULL field [0, p). That uniformity is the whole proof: fix
  // any t-1 shares, and for each candidate secret S there is exactly one
  // coefficient vector that hits those shares with f(0) = S. All p^(t-1) vectors
  // are equally likely, so all p candidate secrets stay equally likely. That is
  // perfect secrecy, and it is the claim the Security Proof tab makes.
  //
  // This code previously drew a_{t-1} from [1, p) "so the polynomial has degree
  // exactly t-1", on the theory that a zero leading term would let t-1 shares
  // reconstruct. That reasoning is wrong on both counts:
  //
  //   * It does not weaken the threshold. The leading coefficient of the unique
  //     interpolant through (0, S) and t-1 shares is an affine, non-degenerate
  //     function of S, so the degree drops for exactly one candidate secret out
  //     of p. Interpolating t-1 shares and reading off f(0) therefore returns the
  //     true secret with probability 1/p — identical to guessing — and the
  //     shareholders cannot tell the degenerate case from the full-degree one,
  //     because the two produce the same observable share values with the same
  //     probabilities. Nothing is detectable, so nothing is exploitable.
  //
  //   * It DID weaken secrecy. Barring 0 made that one candidate secret
  //     unreachable: a holder of t-1 shares could rule it out, so the p
  //     candidates were not equally likely and the perfect-secrecy claim was
  //     false by exactly 1/p. Concretely, for the Security Proof tab's fixed
  //     shares (1,75) and (2,140) over p = 257, the excluded secret was S = 10
  //     (f(x) = 10 + 65x is degree 1 and fits both shares) — a live
  //     counterexample to that tab's own "for every possible secret S" statement.
  //
  // Correctness is untouched: any t points determine a unique polynomial of
  // degree <= t-1, so Lagrange interpolation at x = 0 recovers the secret whether
  // or not the degree happened to drop.
  const coefficients: bigint[] = [secret];
  for (let i = 1; i < t; i++) {
    coefficients.push(await randomBigInt(0n, p));
  }

  const shares: Array<{ x: bigint; y: bigint }> = [];
  for (let i = 1; i <= n; i++) {
    const x = BigInt(i);
    const y = evalPoly(coefficients, x, p);
    shares.push({ x, y });
  }

  return { shares, coefficients };
}

/**
 * Reconstruct secret from exactly t or more shares.
 * Returns f(0) via Lagrange interpolation mod p.
 */
export function reconstructSecret(
  shares: Array<{ x: bigint; y: bigint }>,
  p: bigint
): bigint {
  return lagrangeAt0(shares, p);
}

/**
 * For the security proof: given t-1 shares and a candidate secret S,
 * compute the unique polynomial of degree AT MOST t-1 that passes through the
 * shares AND has f(0) = S. Returns the full coefficient list.
 *
 * This works by treating both (0, S) and the t-1 shares as t points total,
 * then using Lagrange to interpolate the polynomial.
 * The result is deterministic — exactly one such polynomial exists, for EVERY
 * candidate S without exception. (Its leading coefficient is 0 for exactly one
 * S in the field; that polynomial is still a legitimate output of
 * generateShares, which is why generateShares must not exclude it.)
 */
export function polyForSecret(
  shares: Array<{ x: bigint; y: bigint }>,
  candidateSecret: bigint,
  p: bigint
): bigint[] {
  // Augment the t-1 shares with the (0, candidateSecret) point, giving t points
  // that uniquely determine a degree-(t-1) polynomial over GF(p). We recover its
  // power-basis coefficients in two steps: build Newton's divided-difference
  // coefficients, then convert them to standard form so evalPoly() can use them.
  const allPoints = [{ x: 0n, y: candidateSecret }, ...shares];
  const t = allPoints.length; // degree = t-1

  // Newton's divided differences over GF(p):
  const xs = allPoints.map(pt => pt.x);
  let table = allPoints.map(pt => pt.y);

  const coeffs: bigint[] = [((table[0] % p) + p) % p];
  for (let order = 1; order < t; order++) {
    const next: bigint[] = [];
    for (let i = 0; i < table.length - 1; i++) {
      const dx = ((xs[i + order] - xs[i]) % p + p) % p;
      const dy = ((table[i + 1] - table[i]) % p + p) % p;
      next.push((dy * modInverse(dx, p)) % p);
    }
    coeffs.push(((next[0] % p) + p) % p);
    table = next;
  }
  return newtonToStandard(coeffs, xs, p, t);
}

/**
 * Convert Newton forward-difference coefficients to standard power-basis coefficients.
 * This allows evalPoly() to work normally.
 */
function newtonToStandard(newtonCoeffs: bigint[], xs: bigint[], p: bigint, t: number): bigint[] {
  // Standard coefficients via synthetic expansion
  // Start with: result = newtonCoeffs[t-1]
  // For i from t-2 down to 0: result = newtonCoeffs[i] + (x - xs[i]) * result
  // This gives us a polynomial in x. We maintain it as an array of standard coefficients.
  let result: bigint[] = [newtonCoeffs[t - 1]];
  for (let i = t - 2; i >= 0; i--) {
    // result = newtonCoeffs[i] + (x - xs[i]) * result
    // = newtonCoeffs[i] - xs[i]*result[0] + (result[0] + result shift) * x ...
    // Multiply result by (x - xs[i]):
    const shifted: bigint[] = new Array(result.length + 1).fill(0n);
    for (let j = 0; j < result.length; j++) {
      shifted[j + 1] = (shifted[j + 1] + result[j]) % p;
      shifted[j] = (shifted[j] - result[j] * xs[i] % p + p) % p;
    }
    shifted[0] = (shifted[0] + newtonCoeffs[i]) % p;
    result = shifted;
  }
  // Pad to length t
  while (result.length < t) result.push(0n);
  return result;
}

/**
 * Evaluate a polynomial defined by its point set at position x,
 * using Lagrange interpolation. For drawing candidate curves.
 */
export function lagrangeEvalAt(
  points: Array<{ x: bigint; y: bigint }>,
  targetX: bigint,
  p: bigint
): bigint {
  let result = 0n;
  const k = points.length;
  for (let i = 0; i < k; i++) {
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < k; j++) {
      if (i === j) continue;
      num = (num * ((targetX - points[j].x + p * 2n) % p)) % p;
      den = (den * ((points[i].x - points[j].x + p * 2n) % p)) % p;
    }
    const li = (num * modInverse(den, p)) % p;
    result = (result + points[i].y * li) % p;
  }
  return result;
}
