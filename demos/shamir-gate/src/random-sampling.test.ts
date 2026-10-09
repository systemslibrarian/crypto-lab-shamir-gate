import { describe, expect, it, vi } from 'vitest';
import { randomBigInt } from './math';

describe('uniform bounded rejection sampling', () => {
  it('preserves the endpoint of the 257-bit AES-key sharing field', async () => {
    const prime = (1n << 256n) + 297n;
    const draw = vi.spyOn(crypto, 'getRandomValues').mockImplementation((array) => {
      const bytes = array as Uint8Array;
      expect(bytes.length).toBe(33);
      bytes.fill(0);
      bytes[0] = 0xff;
      bytes[31] = 0x01;
      bytes[32] = 0x28;
      return array;
    });
    try {
      expect(await randomBigInt(0n, prime)).toBe(prime - 1n);
      expect(draw).toHaveBeenCalledTimes(1);
    } finally {
      draw.mockRestore();
    }
  });

  it('masks unused entropy bits so a valid field endpoint needs one draw', async () => {
    const draw = vi.spyOn(crypto, 'getRandomValues').mockImplementation((array) => {
      const bytes = array as Uint8Array;
      expect(bytes.length).toBe(2);
      bytes.set([0xff, 0x00]);
      return array;
    });
    try {
      expect(await randomBigInt(0n, 257n)).toBe(256n);
      expect(draw).toHaveBeenCalledTimes(1);
    } finally {
      draw.mockRestore();
    }
  });

  it('rejects the upper bound instead of introducing modulo bias', async () => {
    let calls = 0;
    const draw = vi.spyOn(crypto, 'getRandomValues').mockImplementation((array) => {
      (array as Uint8Array).set(calls++ === 0 ? [0x01, 0x01] : [0x00, 0x00]);
      return array;
    });
    try {
      expect(await randomBigInt(10n, 267n)).toBe(10n);
      expect(draw).toHaveBeenCalledTimes(2);
    } finally {
      draw.mockRestore();
    }
  });

  it('gives every accepted value equal multiplicity across all byte inputs', async () => {
    const counts = new Map<bigint, number>();
    let byte = 0;
    let retry = false;
    const draw = vi.spyOn(crypto, 'getRandomValues').mockImplementation((array) => {
      expect((array as Uint8Array).length).toBe(1);
      (array as Uint8Array)[0] = retry ? 0 : byte;
      retry = true;
      return array;
    });
    try {
      for (byte = 0; byte < 256; byte++) {
        retry = false;
        draw.mockClear();
        const value = await randomBigInt(-20n, -10n);
        const candidate = byte & 15;
        if (candidate < 10) {
          expect(value).toBe(BigInt(candidate) - 20n);
          expect(draw).toHaveBeenCalledTimes(1);
          counts.set(value, (counts.get(value) ?? 0) + 1);
        } else {
          expect(value).toBe(-20n);
          expect(draw).toHaveBeenCalledTimes(2);
        }
      }
      expect(counts.size).toBe(10);
      expect([...counts.values()]).toEqual(Array(10).fill(16));
    } finally {
      draw.mockRestore();
    }
  });

  it('rejects empty/reversed ranges and returns a singleton without entropy', async () => {
    const draw = vi.spyOn(crypto, 'getRandomValues');
    try {
      await expect(randomBigInt(4n, 4n)).rejects.toThrow(RangeError);
      await expect(randomBigInt(5n, 4n)).rejects.toThrow(RangeError);
      expect(await randomBigInt(7n, 8n)).toBe(7n);
      expect(draw).not.toHaveBeenCalled();
    } finally {
      draw.mockRestore();
    }
  });
});
