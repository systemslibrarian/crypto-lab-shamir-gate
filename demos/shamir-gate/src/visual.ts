/**
 * Exact 2-out-of-2 visual secret sharing from Naor--Shamir, Sections 2--3.
 *
 * A source pixel is 0 (white) or 1 (black). Each labeled share receives one
 * of the six four-bit, weight-two patterns. White pixels use the same pattern
 * in both shares; black pixels use complementary patterns. Printed
 * transparencies combine with Boolean OR, never XOR.
 */

import { randomBigInt } from './math';

export type Bit = 0 | 1;
export type Block = readonly [Bit, Bit, Bit, Bit];
export type BitMatrix = Bit[][];
export type PatternDraw = (min: bigint, max: bigint) => Promise<bigint>;

export const MAX_SOURCE_SIDE = 8;

/** The six distinct permutations of two black and two transparent subpixels. */
export const VISUAL_PATTERNS: readonly Block[] = [
  [0, 0, 1, 1],
  [0, 1, 0, 1],
  [0, 1, 1, 0],
  [1, 0, 0, 1],
  [1, 0, 1, 0],
  [1, 1, 0, 0],
] as const;

export interface VisualSharing {
  readonly width: number;
  readonly height: number;
  readonly source: BitMatrix;
  readonly patternIndices: number[];
  readonly share1Blocks: Block[];
  readonly share2Blocks: Block[];
  readonly share1: BitMatrix;
  readonly share2: BitMatrix;
}

export interface DistributionRow {
  readonly share: 1 | 2;
  readonly pattern: string;
  readonly whiteCount: number;
  readonly blackCount: number;
  readonly denominator: number;
}

export interface BasisAnalysis {
  readonly pixelExpansion: number;
  readonly whiteOrWeight: number;
  readonly blackOrWeight: number;
  readonly whiteXorWeight: number;
  readonly blackXorWeight: number;
  readonly contrastNumerator: number;
  readonly contrastDenominator: number;
}

function isBit(value: unknown): value is Bit {
  return value === 0 || value === 1;
}

function cloneMatrix(matrix: BitMatrix): BitMatrix {
  return matrix.map((row) => [...row]);
}

/** Validate a rectangular binary matrix and return its dimensions. */
export function validateBitMatrix(
  matrix: unknown,
  label: string,
  maximumSide = MAX_SOURCE_SIDE * 2,
): { width: number; height: number } {
  if (!Array.isArray(matrix) || matrix.length === 0 || matrix.length > maximumSide) {
    throw new RangeError(`${label} must contain 1 to ${maximumSide} rows.`);
  }
  const first = matrix[0];
  if (!Array.isArray(first) || first.length === 0 || first.length > maximumSide) {
    throw new RangeError(`${label} must contain 1 to ${maximumSide} columns.`);
  }
  const width = first.length;
  for (const row of matrix) {
    if (!Array.isArray(row) || row.length !== width) {
      throw new Error(`${label} must be rectangular.`);
    }
    if (!row.every(isBit)) {
      throw new Error(`${label} must contain only binary cells 0 or 1.`);
    }
  }
  return { width, height: matrix.length };
}

export function hammingWeight(bits: readonly Bit[]): number {
  return bits.reduce<number>((sum, bit) => sum + bit, 0);
}

export function blockKey(block: readonly Bit[]): string {
  if (block.length !== 4 || !block.every(isBit)) {
    throw new Error('A visual-share block must contain exactly four binary subpixels.');
  }
  return block.join('');
}

export function complementBlock(block: Block): Block {
  return block.map((bit) => (bit === 0 ? 1 : 0)) as unknown as Block;
}

export function orBlock(left: Block, right: Block): Block {
  return left.map((bit, index) => (bit | right[index]) as Bit) as unknown as Block;
}

export function xorBlock(left: Block, right: Block): Block {
  return left.map((bit, index) => (bit ^ right[index]) as Bit) as unknown as Block;
}

export function encodeVisualPixel(source: Bit, pattern: Block): { share1: Block; share2: Block } {
  if (!isBit(source)) throw new Error('A source pixel must be 0 (white) or 1 (black).');
  if (hammingWeight(pattern) !== 2) {
    throw new Error('Every visual-share pattern must contain exactly two black subpixels.');
  }
  return {
    share1: [...pattern] as Block,
    share2: source === 0 ? [...pattern] as Block : complementBlock(pattern),
  };
}

/**
 * Draw one of six patterns uniformly. randomBigInt masks to three bits and
 * rejects 6 and 7; it never reduces a byte modulo six.
 */
export async function samplePatternIndex(draw: PatternDraw = randomBigInt): Promise<number> {
  const value = await draw(0n, BigInt(VISUAL_PATTERNS.length));
  if (value < 0n || value >= BigInt(VISUAL_PATTERNS.length)) {
    throw new Error('The pattern sampler returned an out-of-range value.');
  }
  return Number(value);
}

export function blocksToMatrix(
  blocks: readonly Block[],
  width: number,
  height: number,
): BitMatrix {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1) {
    throw new RangeError('Visual-share dimensions must be positive integers.');
  }
  if (blocks.length !== width * height) {
    throw new Error('The number of visual-share blocks does not match the source dimensions.');
  }
  const matrix: BitMatrix = Array.from({ length: height * 2 }, () =>
    Array<Bit>(width * 2).fill(0),
  );
  blocks.forEach((block, index) => {
    if (block.length !== 4 || block.some((bit) => !isBit(bit))) {
      throw new Error('Every visual-share block must contain four binary subpixels.');
    }
    const sourceRow = Math.floor(index / width);
    const sourceColumn = index % width;
    matrix[sourceRow * 2][sourceColumn * 2] = block[0];
    matrix[sourceRow * 2][sourceColumn * 2 + 1] = block[1];
    matrix[sourceRow * 2 + 1][sourceColumn * 2] = block[2];
    matrix[sourceRow * 2 + 1][sourceColumn * 2 + 1] = block[3];
  });
  return matrix;
}

export async function generateVisualShares(
  sourceInput: unknown,
  draw: PatternDraw = randomBigInt,
): Promise<VisualSharing> {
  const { width, height } = validateBitMatrix(sourceInput, 'Source image', MAX_SOURCE_SIDE);
  const source = cloneMatrix(sourceInput as BitMatrix);
  const patternIndices: number[] = [];
  const share1Blocks: Block[] = [];
  const share2Blocks: Block[] = [];

  for (let index = 0; index < width * height; index += 1) {
    const patternIndex = await samplePatternIndex(draw);
    patternIndices.push(patternIndex);
    const pattern = VISUAL_PATTERNS[patternIndex];
    const sourceBit = source[Math.floor(index / width)][index % width];
    const encoded = encodeVisualPixel(sourceBit, pattern);
    share1Blocks.push(encoded.share1);
    share2Blocks.push(encoded.share2);
  }

  return {
    width,
    height,
    source,
    patternIndices,
    share1Blocks,
    share2Blocks,
    share1: blocksToMatrix(share1Blocks, width, height),
    share2: blocksToMatrix(share2Blocks, width, height),
  };
}

export function reconstructExpanded(
  share1Input: unknown | null,
  share2Input: unknown | null,
  operation: 'or' | 'xor',
): BitMatrix {
  if (!share1Input || !share2Input) {
    throw new Error('Both aligned shares are required for reconstruction.');
  }
  const left = validateBitMatrix(share1Input, 'Share 1');
  const right = validateBitMatrix(share2Input, 'Share 2');
  if (left.width !== right.width || left.height !== right.height) {
    throw new Error('The two shares must have identical dimensions.');
  }
  const share1 = share1Input as BitMatrix;
  const share2 = share2Input as BitMatrix;
  return share1.map((row, rowIndex) => row.map((bit, columnIndex) => (
    operation === 'or'
      ? (bit | share2[rowIndex][columnIndex]) as Bit
      : (bit ^ share2[rowIndex][columnIndex]) as Bit
  )));
}

export function stackSharing(sharing: VisualSharing, operation: 'or' | 'xor'): BitMatrix {
  return reconstructExpanded(sharing.share1, sharing.share2, operation);
}

/** Derive expansion and relative contrast from supplied reconstructed blocks. */
export function deriveVisualParameters(
  whiteOr: Block,
  blackOr: Block,
  whiteXor: Block,
  blackXor: Block,
): BasisAnalysis {
  const pixelExpansion = whiteOr.length;
  if ([blackOr, whiteXor, blackXor].some((block) => block.length !== pixelExpansion)) {
    throw new Error('All reconstructed basis blocks must have the same length.');
  }
  const whiteOrWeight = hammingWeight(whiteOr);
  const blackOrWeight = hammingWeight(blackOr);
  const difference = blackOrWeight - whiteOrWeight;
  if (difference <= 0) throw new Error('The black basis must be darker than the white basis.');
  const divisor = gcd(difference, pixelExpansion);
  return {
    pixelExpansion,
    whiteOrWeight,
    blackOrWeight,
    whiteXorWeight: hammingWeight(whiteXor),
    blackXorWeight: hammingWeight(blackXor),
    contrastNumerator: difference / divisor,
    contrastDenominator: pixelExpansion / divisor,
  };
}

function gcd(a: number, b: number): number {
  let x = Math.abs(a);
  let y = Math.abs(b);
  while (y !== 0) [x, y] = [y, x % y];
  return x;
}

export function analyzeVisualBasis(): BasisAnalysis {
  const pattern = VISUAL_PATTERNS[0];
  const complement = complementBlock(pattern);
  return deriveVisualParameters(
    orBlock(pattern, pattern),
    orBlock(pattern, complement),
    xorBlock(pattern, pattern),
    xorBlock(pattern, complement),
  );
}

/** Exhaust the six choices; no Monte Carlo evidence is involved. */
export function enumerateSingleShareDistributions(): DistributionRow[] {
  const counts = new Map<string, number>();
  for (const share of [1, 2] as const) {
    for (const source of [0, 1] as const) {
      for (const pattern of VISUAL_PATTERNS) {
        const encoded = encodeVisualPixel(source, pattern);
        const block = share === 1 ? encoded.share1 : encoded.share2;
        const key = `${share}:${source}:${blockKey(block)}`;
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
    }
  }
  return ([1, 2] as const).flatMap((share) => VISUAL_PATTERNS.map((pattern) => {
    const key = blockKey(pattern);
    return {
      share,
      pattern: key,
      whiteCount: counts.get(`${share}:0:${key}`) ?? 0,
      blackCount: counts.get(`${share}:1:${key}`) ?? 0,
      denominator: VISUAL_PATTERNS.length,
    };
  }));
}

export function reuseOneMask(source: readonly Bit[], patternIndex: number): {
  share2: Block[];
  relations: Array<'equal' | 'complement' | 'neither'>;
} {
  if (source.length < 2 || source.some((bit) => !isBit(bit))) {
    throw new Error('Mask-reuse control needs at least two binary source pixels.');
  }
  if (!Number.isInteger(patternIndex) || patternIndex < 0 || patternIndex >= VISUAL_PATTERNS.length) {
    throw new RangeError('Mask-reuse pattern index is out of range.');
  }
  const share2 = source.map((bit) => encodeVisualPixel(bit, VISUAL_PATTERNS[patternIndex]).share2);
  const relations = share2.slice(1).map((block, index) => {
    const previous = share2[index];
    if (blockKey(block) === blockKey(previous)) return 'equal';
    if (blockKey(block) === blockKey(complementBlock(previous))) return 'complement';
    return 'neither';
  });
  return { share2, relations };
}

export function scrambleOnly(source: readonly Bit[], permutation: readonly number[]): Bit[] {
  if (source.length === 0 || source.some((bit) => !isBit(bit))) {
    throw new Error('Scramble-only input must be a non-empty binary image.');
  }
  if (permutation.length !== source.length) {
    throw new Error('A scramble permutation must name every source position exactly once.');
  }
  const expected = new Set(source.map((_, index) => index));
  if (new Set(permutation).size !== source.length || permutation.some((index) => !expected.has(index))) {
    throw new Error('A scramble permutation must be a bijection of the source positions.');
  }
  return permutation.map((index) => source[index]);
}

export function matrixBits(matrix: unknown): string {
  validateBitMatrix(matrix, 'Bit matrix');
  return (matrix as BitMatrix).map((row) => row.join('')).join('\n');
}
