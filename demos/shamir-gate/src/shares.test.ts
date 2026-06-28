import { describe, it, expect } from 'vitest';
import { parseShareLine, parseShareLines, validateShareSet } from './shares';

describe('parseShareLine', () => {
  it('parses a well-formed x:y:p line', () => {
    expect(parseShareLine('2:140:257')).toEqual({ x: 2n, y: 140n, p: 257n });
  });
  it('tolerates surrounding whitespace', () => {
    expect(parseShareLine('  3 : 9 : 257 ')).toEqual({ x: 3n, y: 9n, p: 257n });
  });
  it('rejects lines without three fields', () => {
    expect(parseShareLine('2:140')).toBeNull();
  });
  it('rejects non-numeric fields', () => {
    expect(parseShareLine('x:140:257')).toBeNull();
  });
});

describe('parseShareLines', () => {
  it('separates good and bad lines', () => {
    const { parsed, badLines } = parseShareLines('1:75:257\ngarbage\n2:140:257');
    expect(parsed).toHaveLength(2);
    expect(badLines).toEqual(['garbage']);
  });
});

describe('validateShareSet — categories of failure', () => {
  it('accepts a clean, consistent share set', () => {
    const r = validateShareSet('1:75:257\n2:140:257\n3:9:257');
    expect(r.ok).toBe(true);
    expect(r.prime).toBe(257n);
    expect(r.shares).toHaveLength(3);
  });

  it('flags empty input as formatting', () => {
    const r = validateShareSet('   ');
    expect(r.ok).toBe(false);
    expect(r.category).toBe('formatting');
  });

  it('flags a malformed line as formatting', () => {
    const r = validateShareSet('1:75:257\nnot-a-share');
    expect(r.ok).toBe(false);
    expect(r.category).toBe('formatting');
  });

  it('flags duplicate x-coordinates as mathematical', () => {
    const r = validateShareSet('2:140:257\n2:99:257');
    expect(r.ok).toBe(false);
    expect(r.category).toBe('mathematical');
  });

  it('flags mismatched primes as operational', () => {
    const r = validateShareSet('1:75:257\n2:140:263');
    expect(r.ok).toBe(false);
    expect(r.category).toBe('operational');
  });

  it('does NOT hard-fail a below-threshold set (interpolation still runs)', () => {
    // Only 2 shares for a 3-of-n split: still "ok" to parse; the wrong-answer
    // lesson is handled by the caller comparing count to the threshold.
    const r = validateShareSet('1:75:257\n2:140:257');
    expect(r.ok).toBe(true);
    expect(r.shares).toHaveLength(2);
  });
});
