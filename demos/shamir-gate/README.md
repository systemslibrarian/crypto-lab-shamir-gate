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

Six interactive tabs:

1. **The Gate** — choose a *t-of-n* threshold, split a text secret into share strings, and reconstruct it. Submitting fewer than *t* shares is rejected with an explanation: interpolation still returns *a* value, but it is not the secret.
2. **Polynomial** — animates the real GF(p) polynomial on a canvas (y wraps mod p; the arithmetic stays exact), toggles share points on and off, and steps through the Lagrange interpolation term by term.
3. **Security Proof** — fixes two shares of a 3-of-n split and shows multiple degree-2 polynomials, each passing through the same two points yet reaching a different secret at x = 0 — making "t-1 shares reveal nothing" tangible.
4. **AES Vault** — generates an AES-256-GCM key, encrypts a message, splits the key into shares, then reconstructs the key from *t* shares and decrypts.
5. **Real World** — where SSS is deployed: FROST (RFC 9591), HSMs, CA key ceremonies, cold storage, two-person rules, and MPC.
6. **Adi Shamir** — a short profile of the *S* in RSA.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-shamir-gate.git
cd crypto-lab-shamir-gate/demos/shamir-gate
npm install
npm run dev        # start the dev server
npm test           # run the GF(p) + AES test suite
npm run build      # typecheck, then build for production
```

The test suite (`src/math.test.ts`, `src/crypto.test.ts`) verifies the field arithmetic,
the share round-trip across **every** t-subset of n, the threshold theorem (for any
candidate secret a consistent polynomial through the t-1 shares exists), and the
end-to-end AES key-split → reconstruct → decrypt flow.

## Part of the Crypto-Lab Suite

This demo is one module in the **Crypto-Lab** collection at [systemslibrarian.github.io/crypto-lab/](https://systemslibrarian.github.io/crypto-lab/).

---

*Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*
