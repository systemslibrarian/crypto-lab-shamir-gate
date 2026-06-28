# Shamir-Gate

## What It Is

Shamir-Gate demonstrates **Shamir's Secret Sharing (SSS)**, the threshold scheme Adi
Shamir published in *How to Share a Secret* (1979). A secret is encoded as the constant
term of a random degree-(t-1) polynomial over a **prime field GF(p)**; each of the *n*
shares is a point `(x, f(x) mod p)`. Any **t** shares reconstruct the secret by Lagrange
interpolation at x = 0; any **t-1** reveal nothing. SSS provides **information-theoretic
security** — below the threshold, every possible secret is equally consistent with the
shares, so the scheme holds even against an adversary with unbounded computing power.

All arithmetic uses JavaScript `BigInt` over a prime modulus — **no floating point in the
math layer**, and all randomness comes from `crypto.getRandomValues`. The demo also pairs
SSS with **AES-256-GCM** (via the Web Crypto API) to show the canonical pattern: encrypt a
message, then split the 256-bit key into threshold shares using the prime `p = 2²⁵⁶ + 297`.

## When to Use It

- **Distributed key custody** — split a master key across parties so no one can decrypt alone (HSM key ceremonies, organizational key escrow).
- **Backup seed phrases** — store a wallet seed as k-of-n shares in separate locations; losing one share does not compromise the seed.
- **Multi-party authorization** — require a quorum (e.g. 3-of-5) to approve a sensitive action; the secret is recoverable only when enough parties cooperate.
- **Threshold file encryption** — combine SSS key-splitting with AES-256-GCM to protect data at rest while distributing trust.
- **When *not* to use it** — plain SSS is not verifiable: shareholders cannot prove a share is valid without revealing it, and a malicious dealer can hand out bad shares. For that, use Verifiable Secret Sharing (VSS) or a threshold signature scheme like FROST.

## Live Demo

[**systemslibrarian.github.io/crypto-lab-shamir-gate/**](https://systemslibrarian.github.io/crypto-lab-shamir-gate/)

Eight interactive tabs:

1. **Lesson** — a guided eight-step arc (encode → field → polynomial → shares → fail below threshold → reconstruct → split a key → limits) with "predict before reveal" checkpoints.
2. **The Gate** — choose a *t-of-n* threshold, split a text secret into share strings, and reconstruct it. Below *t*, interpolation still returns *a* value — surfaced explicitly as **not** the secret.
3. **Polynomial** — animates the GF(p) polynomial on a canvas (y wraps mod p; arithmetic stays exact), toggles share points, steps through Lagrange interpolation, offers a discrete-points view, and renders a text **points table** alternative for screen readers.
4. **Security Proof** — shows multiple degree-2 polynomials through the same two shares, plus an interactive lab: type **any** candidate secret and watch it stay consistent ("observed shares eliminate 0 of 257 possible secrets").
5. **AES Vault** — encrypt with AES-256-GCM, split the key into shares, reconstruct from *t* shares, decrypt. Includes a callout separating encryption / secret-sharing / key-custody and a production-readiness disclaimer.
6. **Failure Lab** — trigger eight deliberate failures (duplicate x, mixed splits, malformed input, sub-threshold, oversized secret, corrupted digit, wrong IV, wrong key share) and see each classified as *formatting*, *mathematical*, *cryptographic*, or *operational*.
7. **Real World** — where SSS is deployed (FROST/RFC 9591, HSMs, CA ceremonies, cold storage, two-person rules, MPC) plus a Sources & standards list.
8. **Adi Shamir** — a short profile of the *S* in RSA.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-shamir-gate.git
cd crypto-lab-shamir-gate/demos/shamir-gate
npm install
npm run dev        # start the dev server
npm test           # run the GF(p) + AES test suite
npm run build      # typecheck, then build for production
```

The test suite (46 tests) verifies the field arithmetic, the share round-trip across
**every** t-subset of n, the threshold theorem (for any candidate secret a consistent
polynomial through the t-1 shares exists), the end-to-end AES key-split → reconstruct →
decrypt flow (`math`/`crypto` specs), the share-validation failure taxonomy (`shares`
spec), and a jsdom UI smoke test (`ui-smoke` spec) that mounts every tab and exercises
the prediction, proof-lab, and failure-lab wiring.

## Part of the Crypto-Lab Suite

This demo is one module in the **Crypto-Lab** collection at [systemslibrarian.github.io/crypto-lab/](https://systemslibrarian.github.io/crypto-lab/).

---

*Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*
