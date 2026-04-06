# crypto-lab-shamir-gate

Interactive Shamir's Secret Sharing (SSS) cryptographic demonstration.

**Location:** `demos/shamir-gate/`

## Quick Start

```bash
cd demos/shamir-gate
npm install
npm run dev
```

Browser opens to http://localhost:5173

## Overview

shamir-gate demonstrates **Shamir's Secret Sharing**, the threshold cryptography scheme invented by **Adi Shamir** in **1979**. The demo visualizes the pure mathematics:

- A **secret is the y-intercept** of a random polynomial over GF(2⁸)
- **Shares are points on the curve** (x, f(x))
- **Any k shares uniquely recover** the polynomial and secret
- **Fewer than k shares reveal nothing** — information-theoretically proven perfect secrecy

## Features

1. **The Gate** — Vault door UI for secret splitting and reconstruction
2. **Polynomial Visualizer** — Real curve rendering showing how shares constrain the polynomial
3. **Security Proof** — Interactive proof that k-1 shares hide the secret perfectly
4. **Message Protection** — AES-256-GCM encryption + Shamir SSS key splitting
5. **Real-world Applications** — HSM, Bitcoin, Signal, nuclear command
6. **Adi Shamir Attribution** — Historical context and original paper

## Technical Stack

| Component | Implementation |
|---|---|
| Finite Field | GF(2⁸) with AES polynomial (0x11b) |
| Arithmetic | Vanilla TypeScript (addition, multiplication, inversion) |
| Polynomial | Horner's method evaluation |
| Interpolation | Lagrange basis polynomials with finite field division |
| Encryption | Web Crypto API: AES-256-GCM |
| Visualization | Canvas 2D with real polynomial curve |
| UI | Vanilla TypeScript, no frameworks |

## All 6 Phases Complete

- ✅ **Phase 1** — GF(2⁸) arithmetic, polynomial evaluation, Shamir SSS, comprehensive tests
- ✅ **Phase 2** — Polynomial curve visualization with canvas rendering
- ✅ **Phase 3** — 5-tab UI: Gate, Visualizer, Security, Uses, Attribution
- ✅ **Phase 4** — Multi-byte secrets, AES-256-GCM key protection, encrypt/decrypt workflow
- ✅ **Phase 5** — Information-theoretic security demonstration with k-1 share enumeration
- ✅ **Phase 6** — Complete documentation and portfolio integration

## Mathematical Foundation

**Shamir's Secret Sharing** works as follows:

**Split:**
1. Create polynomial f(x) of degree k-1 over GF(2⁸) with f(0) = secret
2. Generate n shares: (i, f(i)) for i = 1, 2, ..., n
3. Distribute one share to each party

**Reconstruct:**
1. Given any k shares, use Lagrange interpolation to recover f(x)
2. Evaluate f(0) to recover the secret
3. Fewer than k shares: the system is underdetermined, secret is hidden

**Security:** With k-1 shares, every possible secret is consistent with the known points. All 256 values (for single-byte) are equally likely — perfect secrecy.

## Original Paper

> A. Shamir. "How to Share a Secret." Communications of the ACM, Vol. 22, No. 11, pp. 612–613, November 1979.

## Portfolio Connections

- **frost-threshold**: FROST protocol uses Shamir SSS for distributed key generation
- **silent-tally**: Additive homomorphic Shamir SSS for secure multi-party computation
- **quantum-vault-kpqc**: Threshold file encryption using Shamir SSS for post-quantum key custody
- **kyber-vault**: ML-KEM key encapsulation; keys can be Shamir-split for threshold custody

## Build & Deploy

```bash
npm run build      # Minified production bundle
npm run preview   # Test production build locally
npm test          # Run comprehensive unit tests
```

Output: `dist/` directory with `index.html` and bundled JavaScript

## Testing

All cryptographic primitives verified:
- GF(2⁸) multiplication: gfMul(3, 7) = 9, gfMul(0x53, 0xca) = 0x01
- Polynomial evaluation: Horner's method
- Lagrange interpolation: k shares → unique recovery
- Round-trip: 32-byte secret split/reconstruct byte-for-byte match
- Threshold boundary: k-1 shares fail, k shares succeed
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

**Implementation:** Educational demo for crypto-compare portfolio showcasing threshold cryptography foundations.