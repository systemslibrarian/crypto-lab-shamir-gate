/**
 * Functional coverage for the claims Shamir-Gate makes on screen.
 *
 * The a11y suite reveals every tab and fires every button, but never reads a
 * word of the output, so no verdict, counter or failure path was asserted.
 * These tests assert the load-bearing states, and check the page's numbers
 * against each other and against the field arithmetic redone here in the test:
 * the polynomial the Gate publishes must actually pass through the shares it
 * listed, those shares must interpolate back to the integer it called the
 * secret, the sub-threshold value it prints must be the one Lagrange really
 * gives, and the AES shares must reconstruct the key it displayed. A hardcoded
 * expectation would still pass against a page computing nonsense consistently.
 */
import { expect, test, type Page } from '@playwright/test';

const pageErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  const errors: string[] = [];
  pageErrors.set(page, errors);
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  await page.goto('.');
  await page.locator('.tab-list').waitFor();
});

test.afterEach(async ({ page }) => {
  // A tab that throws mid-render leaves a half-built panel that still satisfies
  // most assertions, so uncaught exceptions have to fail the run.
  expect(pageErrors.get(page) ?? []).toEqual([]);
});

// ---------------------------------------------------------------------------
// GF(p) arithmetic, redone here so the page's output can be checked against it
// ---------------------------------------------------------------------------

interface Point {
  x: bigint;
  y: bigint;
}

const mod = (a: bigint, p: bigint): bigint => ((a % p) + p) % p;

function modPow(base: bigint, exp: bigint, p: bigint): bigint {
  let result = 1n;
  let b = mod(base, p);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % p;
    b = (b * b) % p;
    e >>= 1n;
  }
  return result;
}

/** p is prime throughout this demo, so Fermat gives the inverse. */
const modInv = (a: bigint, p: bigint): bigint => modPow(a, p - 2n, p);

function evalPoly(coeffs: bigint[], x: bigint, p: bigint): bigint {
  let acc = 0n;
  for (let i = coeffs.length - 1; i >= 0; i--) acc = mod(acc * x + coeffs[i]!, p);
  return acc;
}

function lagrangeAt(points: Point[], at: bigint, p: bigint): bigint {
  let total = 0n;
  for (let i = 0; i < points.length; i++) {
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      num = mod(num * mod(at - points[j]!.x, p), p);
      den = mod(den * mod(points[i]!.x - points[j]!.x, p), p);
    }
    total = mod(total + points[i]!.y * num % p * modInv(den, p), p);
  }
  return total;
}

const lagrangeAt0 = (points: Point[], p: bigint): bigint => lagrangeAt(points, 0n, p);

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

function capture(haystack: string, re: RegExp, what: string): string {
  const m = haystack.match(re);
  expect(m, `${what} not found in: ${haystack}`).not.toBeNull();
  return m![1]!;
}

const big = (haystack: string, re: RegExp, what: string): bigint =>
  BigInt(capture(haystack, re, what));

const int = (haystack: string, re: RegExp, what: string): number =>
  Number(capture(haystack, re, what));

function parseShare(serialized: string): { x: bigint; y: bigint; p: bigint } {
  const parts = serialized.split(':');
  expect(parts, `share is not x:y:p — ${serialized}`).toHaveLength(3);
  return { x: BigInt(parts[0]!), y: BigInt(parts[1]!), p: BigInt(parts[2]!) };
}

/** `42 + 17x + 5x^2` → [42n, 17n, 5n] */
function parseCoefficients(expr: string): bigint[] {
  const terms = expr.split('+').map((t) => t.trim());
  return terms.map((t, i) => {
    const digits = capture(t, /^(\d+)/, `coefficient ${i} in "${expr}"`);
    if (i === 1) expect(t).toBe(`${digits}x`);
    if (i > 1) expect(t).toBe(`${digits}x^${i}`);
    return BigInt(digits);
  });
}

async function text(page: Page, selector: string): Promise<string> {
  return (await page.locator(selector).innerText()).replace(/\s+/g, ' ').trim();
}

async function gateShares(page: Page): Promise<string[]> {
  return page
    .locator('#gate-shares-list .share-val')
    .evaluateAll((ns) => ns.map((n) => n.getAttribute('title')!));
}

// ---------------------------------------------------------------------------
// The Gate
// ---------------------------------------------------------------------------

test('gate: the published polynomial passes through the shares it listed, and t of them recover the secret', async ({
  page,
}) => {
  await page.locator('#btn-gate').click();
  await page.locator('#gate-secret').fill('Hello');
  await page.locator('#gate-generate').click();
  await expect(page.locator('#gate-meta')).toBeVisible();

  const meta = await text(page, '#gate-meta');
  const p = big(meta, /Prime used: p = (\d+)/, 'prime');
  const secret = big(meta, /Secret as integer: (\d+)/, 'secret integer');
  const degree = int(meta, /Polynomial degree: (\d+)/, 'degree');
  const bound = int(meta, /at most threshold - 1 = (\d+)/, 'degree bound');
  const coeffs = parseCoefficients(capture(meta, /f\(x\) = (.+?) \(mod p\)/, 'polynomial'));

  const t = Number(await page.locator('#gate-t-val').innerText());
  const n = Number(await page.locator('#gate-n-val').innerText());
  expect(bound).toBe(t - 1);
  expect(coeffs).toHaveLength(t);

  // The secret is the constant term, and the stated degree is the real one.
  expect(coeffs[0]).toBe(secret);
  expect(degree).toBeLessThanOrEqual(bound);
  let actualDegree = coeffs.length - 1;
  while (actualDegree > 0 && coeffs[actualDegree] === 0n) actualDegree--;
  expect(degree).toBe(actualDegree);

  // Every listed share must be a point on that published polynomial, over the
  // published prime — the page cannot show one curve and hand out another.
  const serialized = await gateShares(page);
  expect(serialized).toHaveLength(n);
  const shares = serialized.map(parseShare);
  shares.forEach((s, i) => {
    expect(s.p).toBe(p);
    expect(s.x).toBe(BigInt(i + 1));
    expect(s.y).toBe(evalPoly(coeffs, s.x, p));
  });

  // Any t of them interpolate back to the secret at x = 0.
  expect(lagrangeAt0(shares.slice(0, t), p)).toBe(secret);
  expect(lagrangeAt0(shares.slice(n - t), p)).toBe(secret);

  await page.locator('#gate-shares-input').fill(serialized.slice(0, t).join('\n'));
  await page.locator('#gate-reconstruct').click();

  await expect(page.locator('#gate-result')).toHaveClass(/success/);
  expect(await text(page, '#gate-result')).toBe(
    `✓ Secret recovered: "Hello" (integer: ${secret})`,
  );

  // The vault agrees with the result box.
  await expect(page.locator('#lock-label')).toHaveText('🔓 UNLOCKED');
  await expect(page.locator('#lock-label')).toHaveClass(/unlocked/);
  expect(await text(page, '#lock-progress')).toBe(`Shares collected: ${t} / ${t} needed`);
  await expect(page.locator('#lock-svg')).toHaveAttribute('aria-label', 'Vault unlocked');
  await expect(page.locator('#share-slots .share-slot')).toHaveCount(n);
  await expect(page.locator('#share-slots .share-slot.filled')).toHaveCount(t);
});

test('gate: below the threshold the page prints the value Lagrange really gives, and calls it wrong', async ({
  page,
}) => {
  await page.locator('#btn-gate').click();
  await page.locator('#gate-secret').fill('Hello');
  await page.locator('#gate-generate').click();
  await expect(page.locator('#gate-meta')).toBeVisible();

  const secret = big(await text(page, '#gate-meta'), /Secret as integer: (\d+)/, 'secret integer');
  const t = Number(await page.locator('#gate-t-val').innerText());
  const shares = (await gateShares(page)).map(parseShare);

  const subset = shares.slice(0, t - 1);
  await page
    .locator('#gate-shares-input')
    .fill(subset.map((s) => `${s.x}:${s.y}:${s.p}`).join('\n'));
  await page.locator('#gate-reconstruct').click();

  await expect(page.locator('#gate-result')).toHaveClass(/error/);
  const result = await text(page, '#gate-result');
  expect(result).toContain(`✗ Below threshold: ${t - 1} of ${t} shares`);
  expect(result).toContain('but this is NOT the secret');
  expect(result).toContain('Every possible secret is equally consistent');

  // The printed value is the genuine sub-threshold interpolation — and it is
  // not the secret. Both halves of the lesson, checked.
  const yielded = big(result, /\(integer: (\d+)\)/, 'sub-threshold value');
  expect(yielded).toBe(lagrangeAt0(subset, subset[0]!.p));
  expect(yielded).not.toBe(secret);

  // The vault stays shut and counts what it actually got.
  await expect(page.locator('#lock-label')).toHaveText('🔒 LOCKED');
  expect(await text(page, '#lock-progress')).toBe(`Shares collected: ${t - 1} / ${t} needed`);
  await expect(page.locator('#lock-svg')).toHaveAttribute(
    'aria-label',
    `Vault locked — ${t - 1} of ${t} shares collected`,
  );
  await expect(page.locator('#share-slots .share-slot.filled')).toHaveCount(t - 1);
});

test('gate: a rejected share set names the fault and takes the vault back down', async ({
  page,
}) => {
  // Regression: the reconstruct failure paths returned without touching the
  // vault, so a malformed paste left the previous run's 🔓 UNLOCKED headline
  // standing directly above the failure message.
  await page.locator('#btn-gate').click();
  await page.locator('#gate-generate').click();
  await expect(page.locator('#gate-meta')).toBeVisible();
  const serialized = await gateShares(page);
  const t = Number(await page.locator('#gate-t-val').innerText());

  const cases: Array<{ name: string; input: string; expected: string }> = [
    {
      name: 'malformed line',
      input: `${serialized[0]}\nnot-a-share`,
      expected: 'Malformed share — expected x:y:p but got "not-a-share".',
    },
    {
      name: 'duplicate x',
      input: `1:75:257\n1:99:257`,
      expected:
        'Duplicate share x-coordinates — Lagrange interpolation divides by (xᵢ − xⱼ), which is zero here.',
    },
    {
      name: 'mixed splits',
      input: `1:75:257\n2:140:263`,
      expected: 'Shares use different primes — they come from different splits and cannot be combined.',
    },
    { name: 'nothing entered', input: '', expected: 'No shares entered.' },
  ];

  for (const c of cases) {
    // Unlock first, so a stale UNLOCKED verdict would be visible if it survived.
    await page.locator('#gate-shares-input').fill(serialized.slice(0, t).join('\n'));
    await page.locator('#gate-reconstruct').click();
    await expect(page.locator('#lock-label')).toHaveText('🔓 UNLOCKED');

    await page.locator('#gate-shares-input').fill(c.input);
    await page.locator('#gate-reconstruct').click();

    await expect(page.locator('#gate-result'), c.name).toHaveClass(/error/);
    expect(await text(page, '#gate-result'), c.name).toBe(c.expected);
    await expect(page.locator('#lock-label'), c.name).toHaveText('🔒 LOCKED');
    expect(await text(page, '#lock-progress'), c.name).toBe(`Shares collected: 0 / ${t} needed`);
    await expect(page.locator('#share-slots .share-slot.filled'), c.name).toHaveCount(0);
  }
});

// ---------------------------------------------------------------------------
// Polynomial
// ---------------------------------------------------------------------------

test('polynomial: the points table, the canvas label and the Lagrange stepper all agree', async ({
  page,
}) => {
  await page.locator('#btn-poly').click();
  await page.locator('#poly-secret').fill('42');
  await page.locator('#poly-generate').click();
  await expect(page.locator('#poly-points table')).toBeVisible();

  const t = Number(await page.locator('#poly-t-val').innerText());
  const n = Number(await page.locator('#poly-n-val').innerText());
  const p = BigInt(await page.locator('#poly-p').inputValue());

  const rows = await page
    .locator('#poly-points tbody tr')
    .evaluateAll((ns) => ns.map((r) => [...r.querySelectorAll('th,td')].map((c) => c.textContent!.trim())));
  expect(rows).toHaveLength(n + 1);
  expect(rows[0]).toEqual(['Secret', '0', '42', 'hidden']);

  const points: Point[] = rows.slice(1).map((r) => ({ x: BigInt(r[1]!), y: BigInt(r[2]!) }));
  points.forEach((pt, i) => expect(pt.x).toBe(BigInt(i + 1)));

  // Every plotted point must lie on one polynomial of degree < t whose value at
  // x = 0 is the secret the table declares.
  expect(lagrangeAt0(points.slice(0, t), p)).toBe(42n);
  for (let i = t; i < points.length; i++) {
    expect(lagrangeAt(points.slice(0, t), points[i]!.x, p)).toBe(points[i]!.y);
  }

  // One share starts selected, so the table, the toggles and the canvas must
  // all say "below threshold" together.
  const caption = () => text(page, '#poly-points caption');
  const label = () => page.locator('#poly-canvas').getAttribute('aria-label');
  const pressed = () =>
    page
      .locator('#poly-share-toggles button')
      .evaluateAll((ns) => ns.filter((b) => b.getAttribute('aria-pressed') === 'true').length);

  await expect(page.locator('#poly-share-toggles button')).toHaveCount(n);
  expect(await pressed()).toBe(1);
  expect(await caption()).toBe(
    `Points on f(x) mod ${p} — secret is f(0). 1 of ${t} needed selected (below threshold).`,
  );
  expect(await label()).toContain('Below threshold.');
  expect(await text(page, '#lagrange-stepper')).toContain('Select at least t shares');
  await expect(page.locator('#poly-points tbody tr.row-active')).toHaveCount(1);

  // Select up to the threshold and every one of them must flip together.
  for (let i = 1; i < t; i++) await page.locator('#poly-share-toggles button').nth(i).click();
  expect(await pressed()).toBe(t);
  expect(await caption()).toBe(
    `Points on f(x) mod ${p} — secret is f(0). ${t} of ${t} needed selected (threshold met).`,
  );
  expect(await label()).toContain('Threshold met.');
  await expect(page.locator('#poly-points tbody tr.row-active')).toHaveCount(t);

  // Step the interpolation to its end: one "using shares" step, one L_i(0) per
  // selected share, and the final f(0), which must be the secret.
  const used = points.slice(0, t);
  expect(await text(page, '#lagrange-stepper')).toContain(
    `Using shares: ${used.map((s) => `(${s.x},${s.y})`).join(', ')}`,
  );
  let steps = 1;
  while (await page.locator('#lagrange-next').count()) {
    await page.locator('#lagrange-next').click();
    steps++;
    expect(steps, 'Lagrange stepper did not terminate').toBeLessThan(20);
  }
  expect(steps).toBe(t + 2);
  await expect(page.locator('#lagrange-reset')).toBeVisible();
  await expect(page.locator('.lagrange-step')).toHaveCount(t + 2);

  const stepper = await text(page, '#lagrange-stepper');
  expect(stepper).toContain(`f(0) = ${used.map((s) => s.y).join('·')}`.slice(0, 6));
  expect(stepper).toMatch(/f\(0\) = .* = 42 ✓/);
  expect(stepper).toContain(`mod ${p}`);

  await page.locator('#lagrange-reset').click();
  await expect(page.locator('.lagrange-step')).toHaveCount(1);
});

test('polynomial: a secret outside the field is refused and the bound is named', async ({
  page,
}) => {
  await page.locator('#btn-poly').click();

  await page.locator('#poly-secret').fill('300');
  await page.locator('#poly-generate').click();
  await expect(page.locator('#poly-result')).toHaveClass(/error/);
  expect(await text(page, '#poly-result')).toBe(
    'Secret must be < p (257). Choose a smaller secret or larger p.',
  );
  // Nothing was plotted, so no stale curve is offered as if it were valid.
  await expect(page.locator('#poly-canvas-area')).toBeHidden();
  await expect(page.locator('#poly-share-toggles button')).toHaveCount(0);

  await page.locator('#poly-secret').fill('-5');
  await page.locator('#poly-generate').click();
  await expect(page.locator('#poly-result')).toHaveClass(/error/);
  expect(await text(page, '#poly-result')).toBe('Secret must be a non-negative integer.');
  await expect(page.locator('#poly-canvas-area')).toBeHidden();

  // The same secret inside a bigger field is accepted — the bound is the field,
  // not the number.
  await page.locator('#poly-secret').fill('300');
  await page.locator('#poly-p').selectOption('1021');
  await page.locator('#poly-generate').click();
  await expect(page.locator('#poly-points table')).toBeVisible();
  expect(await text(page, '#poly-points caption')).toContain('mod 1021');
});

// ---------------------------------------------------------------------------
// Security Proof
// ---------------------------------------------------------------------------

test('security proof: every candidate polynomial really does pass through both observed shares', async ({
  page,
}) => {
  const P = 257n;
  await page.locator('#btn-proof').click();

  const candidates = await page
    .locator('#proof-candidates .candidate-poly')
    .evaluateAll((ns) => ns.map((n) => (n as HTMLElement).innerText.replace(/\s+/g, ' ').trim()));
  expect(candidates).toHaveLength(3);

  const secrets = new Set<string>();
  for (const c of candidates) {
    const secret = big(c, /Secret = (\d+):/, 'candidate secret');
    const coeffs = parseCoefficients(
      capture(c, /f\(x\) = (.+?) \(mod 257\)/, 'candidate polynomial').replace(/x²/, 'x^2'),
    );
    expect(coeffs[0]).toBe(secret);
    // The page claims f(1)=75 and f(2)=140; recompute both from its own coefficients.
    expect(c).toContain('f(1)=75 ✓');
    expect(c).toContain('f(2)=140 ✓');
    expect(c).toContain('consistent ✓');
    expect(evalPoly(coeffs, 1n, P)).toBe(75n);
    expect(evalPoly(coeffs, 2n, P)).toBe(140n);
    secrets.add(String(secret));
  }
  // Three different secrets, all consistent — that is the whole argument.
  expect(secrets.size).toBe(3);
});

test('security proof: the lab counts only the candidates it actually verified', async ({ page }) => {
  const P = 257n;
  await page.locator('#btn-proof').click();

  const counter = () => text(page, '#proof-lab-counter');
  expect(await counter()).toBe(
    'You have verified 0 secrets — all consistent. Observed shares eliminate 0 of 257 possible secrets.',
  );

  const check = async (candidate: string): Promise<string> => {
    await page.locator('#proof-candidate').fill(candidate);
    await page.locator('#proof-check').click();
    return text(page, '#proof-lab-out');
  };

  const first = await check('123');
  await expect(page.locator('#proof-lab-out')).toHaveClass(/success/);
  expect(first).toContain('indistinguishable from the real secret');
  const coeffs = parseCoefficients(
    capture(first, /f\(x\) = (.+?) \(mod 257\)/, 'fitted polynomial').replace(/x²/, 'x^2'),
  );
  expect(coeffs[0]).toBe(123n);
  expect(evalPoly(coeffs, 1n, P)).toBe(75n);
  expect(evalPoly(coeffs, 2n, P)).toBe(140n);
  expect(first).toContain('f(1)=75, f(2)=140');
  expect(await counter()).toContain('verified 1 secret —');

  // S = 10 is the degenerate fit the tab stakes its "all 257, no exceptions"
  // claim on: the x² term vanishes and it is still counted as consistent.
  const degenerate = await check('10');
  await expect(page.locator('#proof-lab-out')).toHaveClass(/success/);
  const degCoeffs = parseCoefficients(
    capture(degenerate, /f\(x\) = (.+?) \(mod 257\)/, 'degenerate polynomial').replace(/x²/, 'x^2'),
  );
  expect(degCoeffs[2]).toBe(0n);
  expect(evalPoly(degCoeffs, 1n, P)).toBe(75n);
  expect(evalPoly(degCoeffs, 2n, P)).toBe(140n);
  expect(degenerate).toContain('the x² coefficient came out 0');
  expect(degenerate).toContain('would become "eliminates 1 of 257"');
  expect(await counter()).toContain('verified 2 secrets —');

  // Out of range: rejected, named, and NOT counted as a verification.
  const rejected = await check('300');
  await expect(page.locator('#proof-lab-out')).toHaveClass(/error/);
  expect(rejected).toBe('Enter a candidate secret in [0, 256].');
  expect(await counter()).toContain('verified 2 secrets —');

  // Re-checking a candidate does not inflate the count either.
  await check('123');
  expect(await counter()).toBe(
    'You have verified 2 secrets — all consistent. Observed shares eliminate 0 of 257 possible secrets.',
  );
});

// ---------------------------------------------------------------------------
// AES Vault
// ---------------------------------------------------------------------------

async function aesShares(page: Page): Promise<string[]> {
  return page
    .locator('#aes-shares-list .share-val')
    .evaluateAll((ns) => ns.map((n) => n.getAttribute('title')!));
}

test('aes vault: the shares reconstruct the key it displayed, and t of them decrypt the message', async ({
  page,
}) => {
  await page.locator('#btn-aes').click();
  await page.locator('#aes-message').fill('launch at dawn');
  await page.locator('#aes-generate').click();
  await expect(page.locator('#aes-step2-result')).toBeVisible();

  const t = Number(await page.locator('#aes-t-val').innerText());
  const n = Number(await page.locator('#aes-n-val').innerText());

  const serialized = await aesShares(page);
  expect(serialized).toHaveLength(n);
  const shares = serialized.map(parseShare);
  const p = shares[0]!.p;
  shares.forEach((s, i) => {
    expect(s.x).toBe(BigInt(i + 1));
    expect(s.p).toBe(p);
  });
  // The AES key prime has to be above 2^256 or a 256-bit key would not fit.
  expect(p).toBeGreaterThan(2n ** 256n);

  // Any t shares reconstruct the very key the page put on screen.
  const keyInt = lagrangeAt0(shares.slice(0, t), p);
  const keyHex = keyInt.toString(16).padStart(64, '0');
  const shown = await text(page, '#aes-key-display');
  expect(shown).toBe(`${keyHex.slice(0, 16)}…${keyHex.slice(48)}`);
  expect(lagrangeAt0(shares.slice(n - t), p)).toBe(keyInt);

  // A 12-byte GCM IV, and a ciphertext at least as long as the plaintext.
  const cipherPanel = await text(page, '#aes-cipher-display');
  const iv = capture(cipherPanel, /IV: ([0-9a-f]+)/, 'IV');
  expect(iv).toHaveLength(24);
  // 14 plaintext bytes + the 16-byte GCM tag, as hex.
  const cipherHex = capture(cipherPanel, /CIPHERTEXT: ([0-9a-f]+)/, 'ciphertext');
  expect(cipherHex.length).toBe(2 * ('launch at dawn'.length + 16));

  await page.locator('#aes-shares-input').fill(serialized.slice(0, t).join('\n'));
  await page.locator('#aes-decrypt').click();
  await expect(page.locator('#aes-result')).toHaveClass(/success/);
  expect(await text(page, '#aes-result')).toBe('✓ Decrypted: "launch at dawn"');
});

test('aes vault: every failure path names its cause and returns no plaintext', async ({ page }) => {
  await page.locator('#btn-aes').click();
  await page.locator('#aes-message').fill('launch at dawn');
  await page.locator('#aes-generate').click();
  await expect(page.locator('#aes-step2-result')).toBeVisible();

  const t = Number(await page.locator('#aes-t-val').innerText());
  const serialized = await aesShares(page);

  const attempt = async (input: string): Promise<string> => {
    await page.locator('#aes-shares-input').fill(input);
    await page.locator('#aes-decrypt').click();
    await expect(page.locator('#aes-result')).toHaveClass(/error/);
    const out = await text(page, '#aes-result');
    // Whatever went wrong, the plaintext must not leak out of a failure.
    expect(out).not.toContain('launch at dawn');
    expect(out).not.toContain('Decrypted');
    return out;
  };

  // Below threshold: refused before any decryption is attempted.
  expect(await attempt(serialized.slice(0, t - 1).join('\n'))).toBe(
    `Need at least ${t} shares (got ${t - 1}).`,
  );

  // Malformed input: classified as a format problem, quoting the bad line.
  expect(await attempt(`${serialized[0]}\ngarbage`)).toBe(
    'Malformed share — expected x:y:p but got "garbage".',
  );

  // Duplicate x: the math is undefined, and the message says why.
  expect(await attempt(`${serialized[0]}\n${serialized[0]}`)).toContain(
    'Duplicate share x-coordinates',
  );

  // Regression: a tampered share reconstructs the wrong key, and AES-GCM's tag
  // check rejects it. Chromium's OperationError carries an empty message, which
  // used to render as "Decryption failed:" — a promised reason with nothing
  // after the colon. The tag check must be named.
  const tampered = serialized.slice(0, t);
  const bad = parseShare(tampered[0]!);
  tampered[0] = `${bad.x}:${mod(bad.y + 1n, bad.p)}:${bad.p}`;
  const tamperResult = await attempt(tampered.join('\n'));
  expect(tamperResult).toContain('Decryption failed:');
  expect(tamperResult).toContain('AES-GCM authentication failed');
  expect(tamperResult).not.toMatch(/Decryption failed:\s*$/);
});

// ---------------------------------------------------------------------------
// Failure Lab
// ---------------------------------------------------------------------------

test('failure lab: all eight scenarios fire, classify into the stated taxonomy, and explain', async ({
  page,
}) => {
  await page.locator('#btn-fail').click();
  const buttons = page.locator('#fail-scenarios button');
  await expect(buttons).toHaveCount(8);

  const expected: Array<[string, string, RegExp]> = [
    ['Duplicate x-coordinates', 'MATHEMATICAL', /divides by \(xᵢ − xⱼ\), which is zero here/],
    ['Shares from different splits', 'OPERATIONAL', /different primes — they come from different splits/],
    ['Malformed share text', 'FORMATTING', /expected x:y:p but got "not-a-share"/],
    ['Fewer than t shares', 'MATHEMATICAL', /but the real secret is 42/],
    ['Secret larger than p', 'MATHEMATICAL', /secret must be < p/],
    ['One corrupted digit', 'OPERATIONAL', /instead of 42 — silently/],
    ['Wrong AES IV', 'CRYPTOGRAPHIC', /AES-GCM authentication failed and refused to return any plaintext/],
    ['Wrong AES key share', 'CRYPTOGRAPHIC', /the failure is caught, not silent/],
  ];

  const seen = new Set<string>();
  for (let i = 0; i < expected.length; i++) {
    const [label, category, detail] = expected[i]!;
    await expect(buttons.nth(i)).toHaveText(label);
    await buttons.nth(i).click();
    await expect(page.locator('#fail-output .cat-badge'), label).toBeVisible();
    await expect(page.locator('#fail-output .cat-badge'), label).toHaveText(category);
    const body = await text(page, '#fail-output p');
    expect(body, label).toMatch(detail);
    // "Unexpectedly succeeded" is how a scenario reports that the failure it
    // exists to demonstrate did not actually happen.
    expect(body, label).not.toContain('Unexpectedly succeeded');
    expect(body, label).not.toContain('Unexpected:');
    seen.add(category);
  }

  // The README's claim: four categories, and the lab exercises all of them.
  expect([...seen].sort()).toEqual([
    'CRYPTOGRAPHIC',
    'FORMATTING',
    'MATHEMATICAL',
    'OPERATIONAL',
  ]);

  // The two "confidently wrong" scenarios must actually produce a wrong value —
  // the point is that nothing flags it.
  await buttons.nth(3).click();
  const sub = await text(page, '#fail-output p');
  expect(big(sub, /interpolate to (\d+)/, 'sub-threshold value')).not.toBe(42n);
  await buttons.nth(5).click();
  const corrupted = await text(page, '#fail-output p');
  expect(big(corrupted, /returned (\d+) instead of 42/, 'corrupted value')).not.toBe(42n);
});

// ---------------------------------------------------------------------------
// Lesson
// ---------------------------------------------------------------------------

test('lesson: eight steps walk forward and back, and the checkpoints score the prediction', async ({
  page,
}) => {
  await page.locator('#btn-lesson').click();

  // The progress line is text-transform: uppercase, and innerText reports the
  // transformed text, so compare case-insensitively.
  const progress = async (): Promise<string> =>
    (await text(page, '.lesson-progress')).toLowerCase();
  expect(await progress()).toBe('step 1 of 8');
  await expect(page.locator('#lesson-back')).toBeDisabled();

  // Step 2 carries a prediction checkpoint: answer it wrongly on purpose.
  await page.locator('#lesson-next').click();
  expect(await progress()).toBe('step 2 of 8');
  const options = page.locator('#lesson-body .predict-opt');
  await expect(options).toHaveCount(3);
  await expect(page.locator('#lesson-body .predict-reveal')).toBeHidden();
  await options.nth(0).click();
  await expect(page.locator('#lesson-body .predict-reveal')).toBeVisible();
  expect(await text(page, '#lesson-body .predict-reveal')).toContain('✗ Not quite.');
  expect(await text(page, '#lesson-body .predict-reveal')).toContain('a secret ≥ p would collapse to secret mod p');
  await expect(page.locator('#lesson-body .predict-opt.incorrect')).toHaveCount(1);
  await expect(page.locator('#lesson-body .predict-opt.correct')).toHaveCount(1);
  // Answered means answered — no second guess.
  for (const b of await options.all()) await expect(b).toBeDisabled();

  for (let step = 3; step <= 8; step++) {
    await page.locator('#lesson-next').click();
    expect(await progress()).toBe(`step ${step} of 8`);
  }
  await expect(page.locator('#lesson-next')).toHaveCount(0);
  await expect(page.locator('#lesson-restart')).toBeVisible();

  // The last step is the honest-limits step the README promises.
  const last = await text(page, '#lesson-body');
  expect(last).toContain('Know what SSS does NOT solve');
  expect(last).toContain('VSS');
  expect(last).toContain('FROST');

  await page.locator('#lesson-restart').click();
  expect(await progress()).toBe('step 1 of 8');
  await expect(page.locator('#lesson-back')).toBeDisabled();

  // Answer a checkpoint correctly and it says so.
  await page.locator('#lesson-next').click();
  await page.locator('#lesson-body .predict-opt').nth(1).click();
  expect(await text(page, '#lesson-body .predict-reveal')).toContain('✓ Correct.');
  await page.locator('#lesson-back').click();
  expect(await progress()).toBe('step 1 of 8');
});
