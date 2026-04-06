/**
 * Polynomial Arithmetic over GF(2⁸)
 * 
 * Implements polynomial evaluation and Lagrange interpolation
 * All operations use GF(2⁸) finite field arithmetic
 * 
 * Reference: Shamir, A. (1979). "How to Share a Secret", CACM, 22(11):612-613
 */

import { gfAdd, gfMul, gfDiv, gfSub } from './gf256';

export interface Polynomial {
  /** Coefficients in ascending order: [a₀, a₁, ..., aₖ₋₁]
   * where coefficients[0] = f(0) = the secret
   */
  coefficients: number[];
  /** Polynomial degree (k-1 for k-of-n scheme) */
  degree: number;
  /** Field type indicator */
  field: 'GF256';
}

/**
 * Create a random polynomial of given degree with specified constant term (secret)
 * coefficients[0] = secret
 * coefficients[1..degree] = random values in GF(2⁸)
 */
export function createPolynomial(secret: number, degree: number): Polynomial {
  const coefficients: number[] = [secret & 0xff];

  // Generate random coefficients for x, x², ..., x^degree
  for (let i = 1; i <= degree; i++) {
    coefficients.push(Math.floor(Math.random() * 256));
  }

  return {
    coefficients,
    degree,
    field: 'GF256'
  };
}

/**
 * Evaluate polynomial at x using Horner's method
 * f(x) = a₀ + x(a₁ + x(a₂ + ... + x·aₙ))
 * 
 * All arithmetic in GF(2⁸)
 * This method is O(degree) and numerically stable (critical for real-time visualization)
 */
export function evaluateAt(poly: Polynomial, x: number): number {
  x &= 0xff;
  let result = 0;

  // Horner's method: evaluate from highest degree to lowest
  for (let i = poly.degree; i >= 0; i--) {
    result = gfAdd(gfMul(result, x), poly.coefficients[i]);
  }

  return result;
}

/**
 * Share represents a single point on the polynomial (xᵢ, yᵢ)
 */
export interface Share {
  /** x-coordinate (share index, 1-based, never 0) */
  x: number;
  /** y-coordinate (f(x) evaluated in GF(2⁸)) */
  y: number;
  /** Human-readable label (same as x) */
  index: number;
}

/**
 * Lagrange interpolation: recover f(x) from k shares using Lagrange basis polynomials
 * 
 * f(x) = Σᵢ yᵢ · Lᵢ(x)
 * where Lᵢ(x) = ∏ⱼ≠ᵢ (x - xⱼ) / (xᵢ - xⱼ)
 * 
 * All arithmetic performed in GF(2⁸)
 * Time complexity: O(k²) where k is the number of shares
 * 
 * @param shares Array of k shares (must contain at least k values)
 * @param x Point at which to evaluate the interpolated polynomial
 * @returns Interpolated value f(x)
 */
export function lagrangeInterpolate(shares: Share[], x: number): number {
  if (shares.length === 0) {
    throw new Error('Cannot interpolate with zero shares');
  }

  x &= 0xff;
  let result = 0;

  // Compute Lagrange basis polynomial sum
  for (let i = 0; i < shares.length; i++) {
    const xᵢ = shares[i].x & 0xff;
    const yᵢ = shares[i].y & 0xff;

    // Compute Lagrange basis polynomial Lᵢ(x)
    // Lᵢ(x) = ∏ⱼ≠ᵢ (x - xⱼ) / (xᵢ - xⱼ)
    let numerator = 1;
    let denominator = 1;

    for (let j = 0; j < shares.length; j++) {
      if (j !== i) {
        const xⱼ = shares[j].x & 0xff;

        // numerator *= (x - xⱼ)
        numerator = gfMul(numerator, gfSub(x, xⱼ));

        // denominator *= (xᵢ - xⱼ)
        denominator = gfMul(denominator, gfSub(xᵢ, xⱼ));
      }
    }

    // Lᵢ(x) = numerator / denominator
    const basisValue = gfDiv(numerator, denominator);

    // f(x) += yᵢ * Lᵢ(x)
    result = gfAdd(result, gfMul(yᵢ, basisValue));
  }

  return result;
}

/**
 * Generate n shares from a polynomial
 * Each share is (i, f(i)) for i = 1, 2, ..., n
 */
export function generateShares(poly: Polynomial, n: number): Share[] {
  const shares: Share[] = [];

  for (let i = 1; i <= n; i++) {
    const y = evaluateAt(poly, i);
    shares.push({
      x: i,
      y,
      index: i
    });
  }

  return shares;
}

/**
 * Test polynomial evaluation and interpolation correctness
 */
export function verifyPolynomial(): boolean {
  // Create a polynomial with secret = 73
  const poly = createPolynomial(73, 2);

  // Generate shares
  const shares = generateShares(poly, 5);

  // Verify that interpolating at x=0 recovers the secret
  const recovered = lagrangeInterpolate(shares.slice(0, 3), 0);

  return recovered === 73;
}
