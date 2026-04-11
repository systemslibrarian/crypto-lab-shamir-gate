/**
 * Information-Theoretic Security Proof for Shamir's Secret Sharing
 * 
 * Demonstrates that k-1 shares contain zero information about the secret
 * By showing that all 256 possible secrets are consistent with any k-1 shares
 * 
 * This is perfect secrecy, same security class as the one-time pad
 */

import { Share, createPolynomial, generateShares as generateSharesFromPoly, lagrangeInterpolate } from './polynomial';
import { gfAdd, gfMul, gfSub, gfDiv } from './gf256';

/**
 * For any set of k-1 shares and candidate secret s,
 * find if there exists a polynomial f of degree k-1 such that:
 * - f(0) = s (the secret)
 * - f(xᵢ) = yᵢ for all k-1 shares
 * 
 * Since the polynomial space is k-dimensional (k coefficients)
 * and we have k constraints (including f(0) = s), there is exactly one solution.
 * 
 * For single-byte secrets: all 256 values of s give valid polynomials
 * This proves the information-theoretic security property
 */
export function isSecretConsistent(shares: Share[], candidateSecret: number, k: number): boolean {
  if (shares.length === 0) {
    // With zero shares, all secrets are consistent
    return true;
  }

  // Check if we can construct a polynomial of degree k-1
  // where f(0) = candidateSecret and f(xᵢ) = yᵢ
  //
  // We'll use Gaussian elimination in GF(2⁸) to check consistency
  // Build the system: f(x) = a₀ + a₁x + a₂x² + ...
  //
  // Constraints:
  // a₀ = candidateSecret
  // a₀ + a₁xᵢ + a₂xᵢ² + ... = yᵢ for each share

  // Build augmented matrix [A | b] where:
  // Row 0: [1, 0, 0, ..., 0 | candidateSecret]
  // Row i: [1, xᵢ, xᵢ², ..., xᵢ^(k-1) | yᵢ]

  const matrix: number[][] = [];

  // First row: constraint f(0) = candidateSecret
  const row0 = new Array(k + 1).fill(0);
  row0[0] = 1;
  row0[k] = candidateSecret & 0xff;
  matrix.push(row0);

  // Additional rows: constraints f(xᵢ) = yᵢ
  for (const share of shares) {
    const row = new Array(k + 1).fill(0);
    let xPower = 1; // x⁰ = 1

    for (let col = 0; col < k; col++) {
      row[col] = xPower;
      xPower = gfMul(xPower, share.x);
    }

    row[k] = share.y & 0xff;
    matrix.push(row);
  }

  // Gaussian elimination in GF(2⁸)
  return gaussianEliminationGF256(matrix);
}

/**
 * Gaussian elimination over GF(2⁸) to check if system is consistent
 * Returns true if system has a solution
 */
function gaussianEliminationGF256(matrix: number[][]): boolean {
  const m = matrix.length; // rows
  const n = matrix[0].length - 1; // columns (excluding augmented column)

  let row = 0;

  for (let col = 0; col < n && row < m; col++) {
    // Find pivot
    let pivotRow = -1;
    for (let i = row; i < m; i++) {
      if (matrix[i][col] !== 0) {
        pivotRow = i;
        break;
      }
    }

    if (pivotRow === -1) {
      continue; // No pivot in this column
    }

    // Swap rows
    [matrix[row], matrix[pivotRow]] = [matrix[pivotRow], matrix[row]];

    // Eliminate
    const pivot = matrix[row][col];
    const invPivot = gfDiv(1, pivot);

    // Normalize pivot row
    for (let j = 0; j < matrix[row].length; j++) {
      matrix[row][j] = gfMul(matrix[row][j], invPivot);
    }

    // Eliminate other rows
    for (let i = 0; i < m; i++) {
      if (i !== row && matrix[i][col] !== 0) {
        const factor = matrix[i][col];

        for (let j = 0; j < matrix[i].length; j++) {
          matrix[i][j] = gfSub(matrix[i][j], gfMul(factor, matrix[row][j]));
        }
      }
    }

    row++;
  }

  // Check for inconsistency: any row with all zeros in coefficient columns but non-zero RHS
  for (let i = row; i < m; i++) {
    let allZero = true;
    for (let j = 0; j < n; j++) {
      if (matrix[i][j] !== 0) {
        allZero = false;
        break;
      }
    }

    if (allZero && matrix[i][n] !== 0) {
      return false; // Inconsistent system
    }
  }

  return true; // Consistent system
}

/**
 * Find all consistent secrets for a given set of k-1 shares
 * For single-byte secrets (GF(2⁸)), returns an array of all 256 possible values
 * that are information-theoretically consistent
 *
 * This demonstrates perfect secrecy: with k-1 shares, all secrets are equally likely
 */
export function findAllConsistentSecrets(shares: Share[], k: number): number[] {
  const consistentSecrets: number[] = [];

  // For single-byte secrets over GF(2⁸), try all 256 possible values
  for (let candidateSecret = 0; candidateSecret < 256; candidateSecret++) {
    if (isSecretConsistent(shares, candidateSecret, k)) {
      consistentSecrets.push(candidateSecret);
    }
  }

  return consistentSecrets;
}

/**
 * Verify that with k-1 shares, all 256 secrets are consistent
 * This is the information-theoretic security proof
 */
export function verifySecurityProof(): boolean {
  // Create a polynomial with secret 42 and degree 2 (3-of-n scheme)
  const poly = createPolynomial(42, 2);
  const allShares = generateSharesFromPoly(poly, 5);

  // Take only k-1 = 2 shares
  const kMinusOneShares = allShares.slice(0, 2);

  // Find all consistent secrets
  const consistentSecrets = findAllConsistentSecrets(kMinusOneShares, 3);

  // With k-1 shares, all 256 secrets should be consistent
  if (consistentSecrets.length !== 256) {
    console.log(`Expected 256 consistent secrets, got ${consistentSecrets.length}`);
    return false;
  }

  // Verify that 42 is indeed among them
  if (!consistentSecrets.includes(42)) {
    return false;
  }

  // Test 2: With k shares, only 1 secret should be consistent
  const kShares = allShares.slice(0, 3);
  const consistentSecretsK = findAllConsistentSecrets(kShares, 3);

  if (consistentSecretsK.length !== 1 || consistentSecretsK[0] !== 42) {
    return false;
  }

  return true;
}
