# crypto-lab-shamir-gate

## What It Is

Shamir-Gate demonstrates **Shamir's Secret Sharing (SSS)**, a threshold cryptography scheme invented by Adi Shamir in 1979. The implementation splits secrets into shares using polynomial interpolation over the finite field **GF(2⁸)** with the AES irreducible polynomial (0x11b), then reconstructs them via Lagrange interpolation. SSS provides **information-theoretic security** — with fewer than k shares, every possible secret is equally likely regardless of computational power. The demo also pairs SSS with **AES-256-GCM** (via the Web Crypto API) to show the canonical pattern of encrypting a message, then splitting the encryption key into threshold shares.

## When to Use It

- **Distributed key custody** — Split a master encryption key across multiple parties so no single person can decrypt alone; fits HSM key ceremonies and organizational key escrow.
- **Backup seed phrases** — Store wallet recovery seeds as k-of-n shares in separate geographic locations so that loss of one share does not compromise the seed.
- **Multi-party authorization** — Require a quorum (e.g. 3-of-5 board members) to approve a sensitive action; the secret is only recoverable when enough parties cooperate.
- **Threshold file encryption** — Combine SSS key-splitting with symmetric encryption (AES-256-GCM) to protect files at rest while distributing trust.
- **When NOT to use it** — SSS alone does not provide verifiability; if you need shareholders to prove they hold valid shares without revealing them, use Verifiable Secret Sharing (VSS) or a threshold signature scheme like FROST instead.

## Live Demo

[**systemslibrarian.github.io/crypto-lab-shamir-gate/**](https://systemslibrarian.github.io/crypto-lab-shamir-gate/)

The demo provides five interactive tabs. In **The Gate** tab you configure a k-of-n threshold with sliders (k from 2–6, n from 2–10), split a text secret into share strings, and reconstruct it from any k shares — including an AES-256-GCM encrypt/decrypt workflow that splits the encryption key. The **Polynomial Visualizer** renders the real GF(2⁸) curve on canvas, revealing share points one at a time, and the **Security Proof** tab lets you enumerate all 256 consistent secrets for fewer-than-k shares.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-shamir-gate.git
cd crypto-lab-shamir-gate/demos/shamir-gate
npm install
npm run dev
```

## Part of the Crypto-Lab Suite

This demo is one module in the **Crypto-Lab** collection at [systemslibrarian.github.io/crypto-lab/](https://systemslibrarian.github.io/crypto-lab/).

---

*Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*
- Information-theoretic security: k-1 shares → all 256 secrets consistent
- AES-256-GCM: encrypt → split → reconstruct → decrypt

```bash
npm test
```

## Verification Checklist

- ✓ Every import uses verified packages (vanilla TypeScript only)
- ✓ GF(2⁸) arithmetic correct (test vectors from AES spec)
- ✓ Polynomial visualization shows real curves
- ✓ Share format self-contained and parseable
- ✓ Information-theoretic proof demonstrated by code
- ✓ AES-256-GCM encryption working with key reconstruction
- ✓ Gate visualization shows lock/unlock state
- ✓ No external CDN dependencies (offline capable)
- ✓ All 5 tabs functional and educational
- ✓ Original paper cited in comments and UI

## Browser Requirements

- Modern browsers with Web Crypto API
- ES2020+ support
- No polyfills needed

## File Structure

```
demos/shamir-gate/
├── src/
│   ├── crypto/
│   │   ├── gf256.ts           # GF(2⁸) arithmetic
│   │   ├── polynomial.ts       # Polynomial evaluation & Lagrange
│   │   ├── shamir.ts          # SSS implementation
│   │   ├── security-proof.ts  # Information-theoretic proof
│   │   └── aes.ts             # AES-256-GCM + key import/export
│   ├── visualization/
│   │   └── curve.ts           # Canvas polynomial visualization
│   ├── main.ts                # UI application logic
│   └── style.css              # Styling (dark theme, cyan/magenta)
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
├── vitest.config.ts
└── README.md (this directory)
```

## License

MIT

## Attribution

**Inventor:** Adi Shamir, Weizmann Institute of Science, Israel (1979)

**Implementation:** Educational demo for crypto-lab portfolio showcasing threshold cryptography foundations.