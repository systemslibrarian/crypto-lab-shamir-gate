/**
 * GF(2⁸) Finite Field Arithmetic
 * 
 * Implements addition, multiplication, and inversion in the Galois Field GF(2⁸)
 * using the AES irreducible polynomial: x⁸ + x⁴ + x³ + x + 1 (0x11b)
 * 
 * Reference: FIPS 197 (AES) and standard GF(2⁸) implementations
 */

const PRIMITIVE_POLY = 0x11b; // x⁸ + x⁴ + x³ + x + 1 (AES polynomial)

// Pre-computed logarithm and antilogarithm tables for fast multiplication
const LOG_TABLE = new Uint8Array(256);
const ANTILOG_TABLE = new Uint8Array(256);

/**
 * Initialize log/antilog tables using generator element g=0x03
 * These tables make multiplication O(1) instead of O(8)
 */
function initGFTables(): void {
  let g = 0x01;
  for (let i = 0; i < 255; i++) {
    LOG_TABLE[g] = i;
    ANTILOG_TABLE[i] = g;
    g = gfMulBasic(g, 0x03); // multiply by generator 0x03
  }
  ANTILOG_TABLE[255] = ANTILOG_TABLE[0]; // wrap-around for convenience
  LOG_TABLE[0] = 0; // log(0) = 0 by convention (undefined, but we set to 0)
}

/**
 * Basic GF(2⁸) multiplication without lookup tables (used during table initialization)
 * Uses Russian peasant (repeated squaring) method
 */
function gfMulBasic(a: number, b: number): number {
  let result = 0;
  a &= 0xff;
  b &= 0xff;

  for (let i = 0; i < 8; i++) {
    if (b & (1 << i)) {
      result ^= a << i;
    }
  }

  // Reduce modulo the primitive polynomial
  for (let i = 14; i >= 8; i--) {
    if (result & (1 << i)) {
      result ^= PRIMITIVE_POLY << (i - 8);
    }
  }

  return result & 0xff;
}

/**
 * Addition in GF(2⁸) is XOR
 */
export function gfAdd(a: number, b: number): number {
  return (a ^ b) & 0xff;
}

/**
 * Subtraction in GF(2⁸) is the same as addition (XOR)
 */
export function gfSub(a: number, b: number): number {
  return (a ^ b) & 0xff;
}

/**
 * Multiplication in GF(2⁸) using pre-computed log/antilog tables
 * Optimized for polynomial evaluation at many points
 */
export function gfMul(a: number, b: number): number {
  a &= 0xff;
  b &= 0xff;

  if (a === 0 || b === 0) {
    return 0;
  }

  // log(a*b) = log(a) + log(b) mod 255
  const logSum = (LOG_TABLE[a] + LOG_TABLE[b]) % 255;
  return ANTILOG_TABLE[logSum];
}

/**
 * Multiplicative inverse in GF(2⁸)
 * a * inv(a) = 1
 */
export function gfInv(a: number): number {
  if (a === 0) {
    throw new Error('Cannot invert 0');
  }

  a &= 0xff;

  // inv(a) = a^(-1) = a^254 in GF(2⁸) (since a^255 = 1 for all a ≠ 0)
  // Using antilog table: inv(a) = antilog(255 - log(a))
  return ANTILOG_TABLE[255 - LOG_TABLE[a]];
}

/**
 * Division in GF(2⁸)
 * a / b = a * inv(b)
 */
export function gfDiv(a: number, b: number): number {
  return gfMul(a, gfInv(b));
}

/**
 * Exponentiation in GF(2⁸)
 */
export function gfPow(a: number, n: number): number {
  if (a === 0) {
    return n === 0 ? 1 : 0;
  }

  a &= 0xff;

  // a^n = antilog((log(a) * n) mod 255)
  const logA = LOG_TABLE[a];
  const logResult = (logA * n) % 255;
  return ANTILOG_TABLE[logResult];
}

// Initialize tables on module load
initGFTables();

/**
 * Verify GF(2⁸) arithmetic correctness
 * Test case: gfMul(3, 7) should equal 9
 */
export function verifyGF256(): boolean {
  const test1 = gfMul(3, 7) === 9;
  const test2 = gfMul(0x53, 0xca) === 0x01; // AES test vector
  const test3 = gfInv(0x53) === 0xca; // Inverse test
  const test4 = gfMul(0x95, gfInv(0x95)) === 0x01; // a * inv(a) = 1

  return test1 && test2 && test3 && test4;
}
