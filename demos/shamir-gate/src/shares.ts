/**
 * Share parsing, validation, and failure classification.
 *
 * Pure (no DOM, no crypto side effects) so the Gate, AES Vault, and Failure Lab
 * share one source of truth — and so the teaching claims can be unit-tested.
 *
 * Failure categories deliberately mirror how a practitioner reasons about a broken
 * reconstruction: is it the math, the cryptography, the data format, or the process?
 */

export interface ParsedShare {
  x: bigint;
  y: bigint;
  p: bigint;
}

export type FailureCategory =
  | 'formatting'    // the bytes never parsed as a share
  | 'mathematical'  // the field math is undefined or under-determined
  | 'cryptographic' // authentication / integrity failed (e.g. AES-GCM tag)
  | 'operational';  // valid math, wrong process (mixed splits, too few shares)

export interface ShareValidation {
  ok: boolean;
  shares: ParsedShare[];        // successfully parsed shares (may be partial on failure)
  prime: bigint | null;         // the common prime, when all shares agree
  category?: FailureCategory;
  message?: string;
}

/** Parse a single `x:y:p` line. Returns null if it is not a well-formed share. */
export function parseShareLine(line: string): ParsedShare | null {
  const parts = line.trim().split(':');
  if (parts.length < 3) return null;
  try {
    return { x: BigInt(parts[0]), y: BigInt(parts[1]), p: BigInt(parts[2]) };
  } catch {
    return null;
  }
}

/** Split free text into parsed shares and the lines that failed to parse. */
export function parseShareLines(text: string): { parsed: ParsedShare[]; badLines: string[] } {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  const parsed: ParsedShare[] = [];
  const badLines: string[] = [];
  for (const line of lines) {
    const s = parseShareLine(line);
    if (s) parsed.push(s);
    else badLines.push(line);
  }
  return { parsed, badLines };
}

/**
 * Validate a pasted share set for reconstruction.
 *
 * Returns ok:false with a category + message for the hard failures a learner can
 * trigger. NOTE: "below threshold" is intentionally NOT a hard failure here —
 * interpolation still returns a (wrong) value, and surfacing that confidently-wrong
 * answer is itself the central lesson. Callers compare share count to the threshold.
 */
export function validateShareSet(text: string): ShareValidation {
  const { parsed, badLines } = parseShareLines(text);

  if (parsed.length === 0 && badLines.length === 0) {
    return { ok: false, shares: [], prime: null, category: 'formatting', message: 'No shares entered.' };
  }
  if (badLines.length > 0) {
    return {
      ok: false, shares: parsed, prime: null, category: 'formatting',
      message: `Malformed share — expected x:y:p but got "${badLines[0]}".`,
    };
  }

  const xs = parsed.map(s => s.x.toString());
  if (new Set(xs).size !== xs.length) {
    return {
      ok: false, shares: parsed, prime: parsed[0].p, category: 'mathematical',
      message: 'Duplicate share x-coordinates — Lagrange interpolation divides by (xᵢ − xⱼ), which is zero here.',
    };
  }

  if (parsed.some(s => s.p !== parsed[0].p)) {
    return {
      ok: false, shares: parsed, prime: null, category: 'operational',
      message: 'Shares use different primes — they come from different splits and cannot be combined.',
    };
  }

  return { ok: true, shares: parsed, prime: parsed[0].p };
}
