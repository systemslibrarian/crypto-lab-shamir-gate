# Shamir-Gate

## What It Is

Shamir-Gate demonstrates **Shamir's Secret Sharing (SSS)**, the threshold scheme Adi
Shamir published in *How to Share a Secret* (1979). A secret is encoded as the constant
term of a random polynomial of degree at most t-1 over a **prime field GF(p)** — every
non-constant coefficient, the leading one included, is drawn uniformly from the full field,
which is exactly what makes the sub-threshold view carry no information; each of the *n*
shares is a point `(x, f(x) mod p)`. Any **t** shares reconstruct the secret by Lagrange
interpolation at x = 0; any **t-1** reveal nothing. SSS provides **information-theoretic
security** — below the threshold, every possible secret is equally consistent with the
shares, so the scheme holds even against an adversary with unbounded computing power.

All arithmetic uses JavaScript `BigInt` over a prime modulus — **no floating point in the
math layer**, and all randomness comes from `crypto.getRandomValues`. The demo also pairs
SSS with **AES-256-GCM** (via the Web Crypto API) to show the canonical pattern: encrypt a
message, then split the 256-bit key into threshold shares using the prime `p = 2²⁵⁶ + 297`.

A separate exhibit implements Naor and Shamir's binary **2-out-of-2 visual secret
sharing** construction from Sections 2–3 of *Visual Cryptography* (EUROCRYPT 1994).
Each source pixel draws one of the six four-subpixel weight-two patterns uniformly:
white uses identical share blocks, black uses complementary blocks, and aligned
transparencies reconstruct with Boolean OR. The exhibit exhaustively proves equality of
the complete labeled one-share block distributions; it does not use appearance or
per-subpixel marginals as a substitute for that proof.

## When to Use It

- **Distributed key custody** — split a master key across parties so no one can decrypt alone (HSM key ceremonies, organizational key escrow).
- **Backup seed phrases** — store a wallet seed as k-of-n shares in separate locations; losing one share does not compromise the seed.
- **Multi-party authorization** — require a quorum (e.g. 3-of-5) to approve a sensitive action; the secret is recoverable only when enough parties cooperate.
- **Threshold file encryption** — combine SSS key-splitting with AES-256-GCM to protect data at rest while distributing trust.
- **Visual 2-of-2 teaching** — examine pixel expansion, physical OR reconstruction,
  exact one-share privacy, and mask-reuse failure in the bounded binary construction.
- **When *not* to use it** — plain SSS is not verifiable: shareholders cannot prove a share is valid without revealing it, and a malicious dealer can hand out bad shares. For that, use Verifiable Secret Sharing (VSS) or a threshold signature scheme like FROST.

## Live Demo

[**systemslibrarian.github.io/crypto-lab-shamir-gate/**](https://systemslibrarian.github.io/crypto-lab-shamir-gate/)

Nine interactive tabs:

1. **Lesson** — a guided eight-step arc (encode → field → polynomial → shares → fail below threshold → reconstruct → split a key → limits) with "predict before reveal" checkpoints.
2. **The Gate** — choose a *t-of-n* threshold, split a text secret into share strings, and reconstruct it. Below *t*, interpolation still returns *a* value — surfaced explicitly as **not** the secret.
3. **Polynomial** — animates the GF(p) polynomial on a canvas (y wraps mod p; arithmetic stays exact), toggles share points, steps through Lagrange interpolation, offers a discrete-points view, and renders a text **points table** alternative for screen readers.
4. **Security Proof** — shows multiple polynomials of degree ≤ 2 through the same two shares, plus an interactive lab: type **any** candidate secret and watch it stay consistent ("observed shares eliminate 0 of 257 possible secrets"). All 257 secrets qualify, including S = 10, whose fit is the degree-1 line f(x) = 10 + 65x — a generator that forced the leading coefficient nonzero could never produce it, and the count would be 1 of 257 eliminated rather than 0.
5. **Visual Shares** — edit a bounded binary image, draw a fresh exact-uniform mask for every pixel, inspect both expanded shares, reconstruct from their actual bits with physical OR, compare digital XOR, enumerate every one-share block probability, and run mask-reuse, scramble-only, and missing-share controls. The browser explicitly does not model printing, alignment error, opacity, authenticity, or general k-of-n visual cryptography.
6. **AES Vault** — encrypt with AES-256-GCM, split the key into shares, reconstruct from *t* shares, decrypt. Includes a callout separating encryption / secret-sharing / key-custody and a production-readiness disclaimer.
7. **Failure Lab** — trigger eight deliberate failures (duplicate x, mixed splits, malformed input, sub-threshold, oversized secret, corrupted digit, wrong IV, wrong key share) and see each classified as *formatting*, *mathematical*, *cryptographic*, or *operational*.
8. **Real World** — where SSS is deployed (FROST/RFC 9591, HSMs, CA ceremonies, cold storage, two-person rules, MPC) plus a Sources & standards list.
9. **Adi Shamir** — a short profile of the *S* in RSA.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-shamir-gate.git
cd crypto-lab-shamir-gate/demos/shamir-gate
npm install
npm run dev        # start the dev server
npm test           # run the GF(p) + AES test suite
npm run build      # typecheck, then build for production
npm run test:e2e   # Playwright: functional claims + WCAG 2.1 AA gate
npm run test:mutations # clean baseline + 14 focused visual-sharing mutations
```

`npm run test:e2e` (and `test:a11y`, the same run) builds first and serves the
production bundle, so what is driven is what ships.

**Functional browser gate:** `e2e/claims.spec.ts` drives the built page and asserts the
numbers each tab puts on screen — checked against each other and against the GF(p)
arithmetic redone inside the test, not against constants. The polynomial the Gate
publishes must actually pass through the shares it listed and its constant term must be
the integer it called the secret; any t of those shares must interpolate back to it; the
sub-threshold value it prints must be the one Lagrange really gives *and* must differ
from the secret; the Polynomial tab's points must all lie on one degree-<t curve while
its table caption, canvas label and Lagrange stepper agree on whether the threshold is
met; every Security Proof candidate must genuinely evaluate to f(1)=75 and f(2)=140; and
the AES shares must reconstruct the very key displayed above them. Every failure path is
asserted to reach its state *and* name its cause — malformed, duplicate-x, mixed-split
and empty share sets, an out-of-field secret, a below-threshold decrypt, and a tampered
key share, which must fail the GCM tag check and leak no plaintext. Uncaught page
exceptions fail the run. The visual-sharing browser checks parse the rendered source and
share bit matrices, independently recompute every same/complement relation and OR/XOR
cell, derive weights and contrast, enumerate the visible distribution table, exercise all
three controls, and prove stale results retire when the source or size changes.

The unit suite (73 tests) verifies the field arithmetic, the share round-trip across
**every** t-subset of n, the threshold theorem (for any candidate secret a consistent
polynomial through the t-1 shares exists), the end-to-end AES key-split → reconstruct →
decrypt flow (`math`/`crypto` specs), the share-validation failure taxonomy (`shares`
spec), all six visual patterns and their complete distributions, exact OR/XOR behavior,
rejection sampling, malformed-input refusals and negative controls (`visual` spec), and a
jsdom UI smoke test (`ui-smoke` spec) that mounts every tab and exercises the prediction,
proof-lab, visual-sharing, and failure-lab wiring. The hosted clean-baseline mutation gate
kills 14 named changes and reruns the restored baseline.

## Visual-sharing source and limits

- Moni Naor and Adi Shamir, [*Visual Cryptography*](https://doi.org/10.1007/BFb0053419),
  EUROCRYPT 1994, Sections 2–3. Section 2 defines contrast and security through full
  restricted-matrix distributions. Section 3 gives the 2-of-2 same/complement rule and
  recommends four subpixels in a 2×2 array to avoid aspect-ratio distortion.
- The implementation is a bounded binary 2-of-2 teaching model. It is not a general
  k-of-n, grayscale, color, progressive, authenticated, or production distribution
  system. It assumes aligned shares and does not model printing or optical behavior.
- XOR is shown only as a digital comparison. Printed black ink is monotone, so physical
  stacking is Boolean OR. Scrambling-only and mask-reuse controls are bounded
  counterexamples, not universal claims about unrelated constructions.

## Part of the Crypto-Lab Suite

This demo is one module in the **Crypto-Lab** collection at [systemslibrarian.github.io/crypto-lab/](https://systemslibrarian.github.io/crypto-lab/).

---

*Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*
