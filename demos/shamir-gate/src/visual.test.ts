import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  VISUAL_PATTERNS,
  analyzeVisualBasis,
  blockKey,
  blocksToMatrix,
  complementBlock,
  deriveVisualParameters,
  encodeVisualPixel,
  enumerateSingleShareDistributions,
  generateVisualShares,
  hammingWeight,
  matrixBits,
  orBlock,
  reconstructExpanded,
  reuseOneMask,
  samplePatternIndex,
  scrambleOnly,
  stackSharing,
  validateBitMatrix,
  xorBlock,
  type Bit,
  type Block,
} from './visual';

afterEach(() => vi.unstubAllGlobals());

describe('Naor--Shamir four-subpixel basis', () => {
  it('enumerates exactly the six distinct weight-two patterns in canonical order', () => {
    expect(VISUAL_PATTERNS.map(blockKey)).toEqual([
      '0011', '0101', '0110', '1001', '1010', '1100',
    ]);
    expect(new Set(VISUAL_PATTERNS.map(blockKey)).size).toBe(6);
    expect(VISUAL_PATTERNS.every((pattern) => hammingWeight(pattern) === 2)).toBe(true);
  });

  it('complementation is a bijection of the same six patterns', () => {
    const keys = new Set(VISUAL_PATTERNS.map(blockKey));
    const complements = VISUAL_PATTERNS.map((pattern) => blockKey(complementBlock(pattern)));
    expect(new Set(complements)).toEqual(keys);
  });

  it('keeps either labeled share weight two for both source colors', () => {
    for (const source of [0, 1] as const) {
      for (const pattern of VISUAL_PATTERNS) {
        const { share1, share2 } = encodeVisualPixel(source, pattern);
        expect(hammingWeight(share1)).toBe(2);
        expect(hammingWeight(share2)).toBe(2);
        expect(VISUAL_PATTERNS.map(blockKey)).toContain(blockKey(share1));
        expect(VISUAL_PATTERNS.map(blockKey)).toContain(blockKey(share2));
      }
    }
    expect(() => encodeVisualPixel(0, [0, 0, 0, 1])).toThrow(/exactly two black/);
  });

  it('uses identical rows for white and complementary rows for black', () => {
    for (const pattern of VISUAL_PATTERNS) {
      expect(blockKey(encodeVisualPixel(0, pattern).share2)).toBe(blockKey(pattern));
      expect(blockKey(encodeVisualPixel(1, pattern).share2)).toBe(blockKey(complementBlock(pattern)));
    }
  });

  it('derives every OR and XOR reconstruction weight exhaustively', () => {
    for (const pattern of VISUAL_PATTERNS) {
      const white = encodeVisualPixel(0, pattern);
      const black = encodeVisualPixel(1, pattern);
      expect(hammingWeight(orBlock(white.share1, white.share2))).toBe(2);
      expect(hammingWeight(orBlock(black.share1, black.share2))).toBe(4);
      expect(blockKey(xorBlock(white.share1, white.share2))).toBe('0000');
      expect(blockKey(xorBlock(black.share1, black.share2))).toBe('1111');
    }
  });

  it('derives pixel expansion and one-half contrast from the basis blocks', () => {
    expect(analyzeVisualBasis()).toEqual({
      pixelExpansion: 4,
      whiteOrWeight: 2,
      blackOrWeight: 4,
      whiteXorWeight: 0,
      blackXorWeight: 4,
      contrastNumerator: 1,
      contrastDenominator: 2,
    });
    expect(deriveVisualParameters(
      [0, 0, 0, 1],
      [1, 1, 1, 1],
      [0, 0, 0, 0],
      [1, 1, 1, 1],
    )).toMatchObject({ contrastNumerator: 3, contrastDenominator: 4 });
  });
});

describe('exact one-share privacy', () => {
  it('enumerates identical full block distributions, one of six each', () => {
    const rows = enumerateSingleShareDistributions();
    expect(rows).toHaveLength(12);
    for (const row of rows) {
      expect(row.whiteCount).toBe(1);
      expect(row.blackCount).toBe(1);
      expect(row.denominator).toBe(6);
    }
    for (const share of [1, 2]) {
      const selected = rows.filter((row) => row.share === share);
      expect(selected.reduce((sum, row) => sum + row.whiteCount, 0)).toBe(6);
      expect(selected.reduce((sum, row) => sum + row.blackCount, 0)).toBe(6);
    }
  });
});

describe('generation, reconstruction and validation', () => {
  it('draws independently for every pixel and round-trips solely from the shares', async () => {
    const source: Bit[][] = [[0, 1, 0], [1, 1, 0]];
    const draws = [0n, 1n, 2n, 3n, 4n, 5n];
    const observedRanges: Array<[bigint, bigint]> = [];
    const sharing = await generateVisualShares(source, async (min, max) => {
      observedRanges.push([min, max]);
      return draws.shift()!;
    });
    expect(observedRanges).toEqual(Array(6).fill([0n, 6n]));
    expect(sharing.patternIndices).toEqual([0, 1, 2, 3, 4, 5]);
    expect(sharing.share1).toHaveLength(4);
    expect(sharing.share1[0]).toHaveLength(6);

    const or = stackSharing(sharing, 'or');
    const xor = stackSharing(sharing, 'xor');
    for (let index = 0; index < source.flat().length; index += 1) {
      const row = Math.floor(index / source[0].length);
      const column = index % source[0].length;
      const orBlockFromMatrix: Block = [
        or[row * 2][column * 2], or[row * 2][column * 2 + 1],
        or[row * 2 + 1][column * 2], or[row * 2 + 1][column * 2 + 1],
      ];
      const xorBlockFromMatrix: Block = [
        xor[row * 2][column * 2], xor[row * 2][column * 2 + 1],
        xor[row * 2 + 1][column * 2], xor[row * 2 + 1][column * 2 + 1],
      ];
      expect(hammingWeight(orBlockFromMatrix)).toBe(source[row][column] === 0 ? 2 : 4);
      expect(blockKey(xorBlockFromMatrix)).toBe(source[row][column] === 0 ? '0000' : '1111');
    }
  });

  it('uses rejection sampling through randomBigInt rather than byte modulo six', async () => {
    const bytes = [6, 7, 5];
    const calls: number[] = [];
    vi.stubGlobal('crypto', {
      getRandomValues<T extends ArrayBufferView>(view: T): T {
        const target = view as Uint8Array;
        const next = bytes.shift();
        if (next === undefined) throw new Error('test entropy exhausted');
        target[0] = next;
        calls.push(next);
        return view;
      },
    });
    expect(await samplePatternIndex()).toBe(5);
    expect(calls).toEqual([6, 7, 5]);
  });

  it('rejects an injected sampler outside the declared six-pattern range', async () => {
    await expect(samplePatternIndex(async () => 6n)).rejects.toThrow(/out-of-range/);
  });

  it('refuses missing, malformed and mismatched shares instead of truncating', () => {
    const valid: Bit[][] = [[0, 1], [1, 0]];
    expect(() => reconstructExpanded(valid, null, 'or')).toThrow(/Both aligned shares/);
    expect(() => reconstructExpanded(valid, [[0]], 'or')).toThrow(/identical dimensions/);
    expect(() => reconstructExpanded(valid, [[0, 1], [1, 2]], 'or')).toThrow(/only binary/);
    expect(() => validateBitMatrix([], 'Empty')).toThrow(/1 to/);
    expect(() => validateBitMatrix([[0], [0, 1]], 'Ragged')).toThrow(/rectangular/);
  });

  it('refuses malformed blocks and wrong block counts', () => {
    expect(() => blocksToMatrix([], 1, 1)).toThrow(/does not match/);
    expect(() => blocksToMatrix([[0, 0, 0, 0] as Block], 0, 1)).toThrow(/positive/);
    expect(() => blockKey([0, 1] as unknown as Block)).toThrow(/exactly four/);
  });

  it('rejects zero, oversized, ragged and non-binary source grids', async () => {
    await expect(generateVisualShares([])).rejects.toThrow(/1 to 8 rows/);
    await expect(generateVisualShares(Array.from({ length: 9 }, () => [0]))).rejects.toThrow(/1 to 8 rows/);
    await expect(generateVisualShares([[0], [0, 1]])).rejects.toThrow(/rectangular/);
    await expect(generateVisualShares([[2]])).rejects.toThrow(/only binary/);
  });

  it('serializes the accessible bit matrix exactly', () => {
    expect(matrixBits([[0, 1], [1, 0]])).toBe('01\n10');
  });
});

describe('negative controls', () => {
  it('shows exact equality/complement leakage when one mask is reused', () => {
    const leaked = reuseOneMask([0, 0, 1, 1], 0);
    expect(leaked.share2.map(blockKey)).toEqual(['0011', '0011', '1100', '1100']);
    expect(leaked.relations).toEqual(['equal', 'complement', 'equal']);
  });

  it('shows that position scrambling preserves a distinguishing black count', () => {
    const light: Bit[] = [1, 1, 0, 0, 0, 0, 0, 0];
    const dark: Bit[] = [1, 1, 1, 1, 1, 0, 0, 0];
    const reverse = light.map((_, index) => light.length - 1 - index);
    const scrambledLight = scrambleOnly(light, reverse);
    const scrambledDark = scrambleOnly(dark, reverse);
    expect(hammingWeight(scrambledLight)).toBe(2);
    expect(hammingWeight(scrambledDark)).toBe(5);
    expect(hammingWeight(scrambledLight)).not.toBe(hammingWeight(scrambledDark));
  });

  it('refuses non-bijections in the scramble-only control', () => {
    expect(() => scrambleOnly([0, 1], [0, 0])).toThrow(/bijection/);
    expect(() => scrambleOnly([0, 1], [0])).toThrow(/every source position/);
  });
});
