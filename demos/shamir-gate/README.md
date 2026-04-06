# Shamir-Gate — Interactive Shamir's Secret Sharing Demo

## Overview

**shamir-gate** is a browser-based cryptographic demonstration of **Shamir's Secret Sharing (SSS)**, the groundbreaking threshold cryptography scheme invented by **Adi Shamir** at the Weizmann Institute of Science in **1979**.

The demo showcases the pure mathematics of polynomial interpolation over finite fields, where:
- A **secret is the y-intercept** of a random polynomial
- **Shares are points on the curve** (x, f(x)) for x = 1, 2, ..., n
- **Any k shares uniquely determine** the polynomial and recover the secret
- **Fewer than k shares reveal nothing** — perfect secrecy, information-theoretically proven

### Key Innovation

Shamir's Secret Sharing is **information-theoretically secure** — the security does not depend on computational difficulty (like AES) but on mathematical proof: with k-1 shares, every possible secret is equally likely, so an attacker gains zero information regardless of compute power.

## Features

### 1. **The Gate** — Vault Door Metaphor
- Configure k-of-n threshold
- Split any secret into n shares
- Reconstruct from any k shares
- Visualize the threshold boundary: need exactly k shares, not k-1

### 2. **Polynomial Visualizer** — Real Curve Rendering
- 2D canvas visualization of the underlying polynomial
- Share points on the curve
- Animate share reveal: watch the curve become constrained
- See x=0 (the secret location) emerge as shares accumulate

### 3. **Security Proof** — Information-Theoretic Guarantee
- Interactive demonstration that k-1 shares reveal all 256 possible secrets equally
- Verify perfect secrecy by enumeration
- Compare with computational security (AES): SSS is stronger (proven, not assumed)

### 4. **Message Protection** — AES-256-GCM + SSS
- Generate random AES-256-GCM key
- Encrypt a message using Web Crypto API
- Split the key into n shares with Shamir SSS
- Reconstruct any k shares → recover key → decrypt message
- Demonstrates production pattern: SSS protects encryption keys

### 5. **Real-world Applications**
- Hardware Security Modules (HSM) master key ceremonies
- Bitcoin multisig (threshold signature vs. threshold key splitting)
- Signal's sealed sender (multi-device key distribution)
- Nuclear command authority (two-person integrity)
- Portfolio integration: foundation of frost-threshold, silent-tally, quantum-vault-kpqc

### 6. **Historical Attribution** — Adi Shamir
- Weizmann Institute of Science, Israel
- Co-inventor of RSA (Rivest-Shamir-Adleman)
- Original 1979 paper: "How to Share a Secret", Communications of the ACM

## How to Run Locally

### Prerequisites
- Node.js 18+ and npm

### Installation
```bash
cd demos/shamir-gate
npm install
npm run dev
```

Browser opens to `http://localhost:5173`

### Build for Production
```bash
npm run build
npm run preview  # test production build locally
```

## Implementation Details

### Cryptography Stack

| Layer | Implementation |
|---|---|
| **Finite Field** | GF(2⁸) using AES irreducible polynomial (0x11b = x⁸ + x⁴ + x³ + x + 1) |
| **Arithmetic** | Vanilla TypeScript: GF(2⁸) add (XOR), multiply (log tables), invert |
| **Polynomial** | Horner's method for O(degree) evaluation |
| **Interpolation** | Lagrange basis polynomials with GF(2⁸) division |
| **Key Splitting** | Byte-level: each byte split independently with same k, different coefficients |
| **Encryption** | Web Crypto API: AES-256-GCM (authenticated encryption) |

### GF(2⁸) Arithmetic

All operations use finite field arithmetic over GF(2⁸):

```typescript
gfAdd(a, b)      // XOR
gfMul(a, b)      // Using pre-computed log/antilog tables
gfDiv(a, b)      // a * inv(b)
gfInv(a)         // Multiplicative inverse
```

**Why GF(2⁸)?** 
- AES-compatible (same field as AES)
- Byte-level granularity (natural for cryptography)
- Efficient: 256 values fit in one byte
- Secure: field operations are well-studied

### Polynomial Evaluation

Horner's method ensures O(degree) time and numerical stability:

```
f(x) = a₀ + x(a₁ + x(a₂ + ... + x·aₙ))
```

All arithmetic is GF(2⁸), so evaluation is exact (no floating-point).

### Lagrange Interpolation

Given k shares (xᵢ, yᵢ), recover f(x) at any x:

```
f(x) = Σᵢ yᵢ · Lᵢ(x)
```

where the basis polynomial is:

```
Lᵢ(x) = ∏ⱼ≠ᵢ (x - xⱼ) / (xᵢ - xⱼ)
```

All arithmetic in GF(2⁸). To recover secret: evaluate at x=0.

### Share Format

Self-contained, no external context needed:

```
shamir-gate-v1:{k}:{n}:{index}:{hex_y_values}
```

Example (3-of-5 scheme, share 2, 2-byte secret):
```
shamir-gate-v1:3:5:2:a4f2c8d1
```

Fields:
- `k`: threshold
- `n`: total shares
- `index`: share number (1 to n)
- `hex_y_values`: y-values for each secret byte, hex-encoded

### Multi-byte Secrets

Each byte split independently:

1. For each byte b in secret:
   - Create polynomial f(x) of degree k-1 with f(0) = b
   - Generate shares (1, f(1)), (2, f(2)), ..., (n, f(n))
   - Each shareholder gets one y-value from each polynomial

2. Result: n sharessets, each with k-level threshold, independent polynomials hidden from each other

## Mathematical Foundation

**Theorem (Shamir, 1979):** 
Over a finite field, a polynomial of degree k-1 is uniquely determined by k points.

**Security Property:**
With exactly k-1 points, infinitely many degree-(k-1) polynomials pass through them. In GF(2⁸), for any candidate secret s, there exists a valid polynomial f(0) = s and f(xᵢ) = yᵢ for all given shares.

**Proof:** The system of k-1 equations in k unknowns (coefficients a₀, a₁, ..., aₖ₋₁) is underdetermined. Any s determines a unique solution, so all secrets are equally likely — perfect secrecy.

## Testing

Unit tests verify:
- GF(2⁸) correctness (test vectors from AES spec)
- Polynomial evaluation and interpolation
- Round-trip: split → reconstruct → verify byte-for-byte match
- Threshold boundary: k-1 shares fail, k shares succeed
- Security proof: k-1 shares → all 256 secrets consistent
- Share serialization/deserialization
- AES round-trip: split key → encrypt → reconstruct → decrypt

To run tests:
```bash
npm test
```

## Architectural Highlights

### Vanilla TypeScript
- No external crypto libraries (implements SSS from first principles)
- No frameworks (pure DOM manipulation + inline styles)
- Tree-shakeable: only code used gets bundled
- ~15KB minified + gzip for entire app

### Real Polynomial Visualization
- Canvas rendering of actual polynomial over GF(2⁸)
- Not conceptual diagrams — real math visualized
- Smooth animation as shares are revealed
- Coordinate system: x ∈ [0, 15], y ∈ [0, 255]

### Information-Theoretic Proof
- Code implements the proof: k-1 shares → enumerate all 256 possible secrets
- Every secret is consistent with the given shares
- Demonstrates perfect secrecy in practice

## Verification Checklist

- ✓ GF(2⁸) arithmetic verified: gfMul(3, 7) = 9, gfMul(0x53, 0xca) = 0x01
- ✓ Polynomial evaluation: Horner's method, O(degree)
- ✓ Lagrange interpolation: k shares → unique polynomial
- ✓ Round-trip: 32-byte AES key split/reconstruct byte-for-byte match
- ✓ Threshold: k-1 shares fail, k shares succeed
- ✓ Security: k-1 shares enumeration finds all 256 secrets
- ✓ Share format: self-contained, parseable without context
- ✓ AES-GCM: encrypt message → split key → reconstruct → decrypt
- ✓ Visualization: real polynomial curve rendering
- ✓ Offline: no external dependencies, works fully offline

## Browser Compatibility

- Modern browsers with Web Crypto API (Chrome 37+, Firefox 34+, Safari 11+, Edge 79+)
- Requires ES2020+ (async/await, BigInt, const/let)

## References

**Original Paper:**
> A. Shamir. "How to Share a Secret." Communications of the ACM, Vol. 22, No. 11, pp. 612–613, November 1979.

**Cryptographic Standards:**
- FIPS 197 (AES) — GF(2⁸) arithmetic, irreducible polynomial
- NIST SP 800-38D (GCM) — Authenticated encryption mode

**Portfolio Connections:**
- **frost-threshold**: FROST protocol for threshold signatures (uses Shamir SSS for distributed key generation)
- **silent-tally**: Additive homomorphic SSS for secure multi-party computation
- **quantum-vault-kpqc**: Threshold file encryption using SSS to split AES keys for quantum-resistant custody
- **kyber-vault**: ML-KEM key encapsulation (post-quantum); keys could be Shamir-split for threshold custody

## License

MIT

## Author

Crypto Compare Portfolio — Educational cryptographic demos showcasing mathematical foundations and real-world applications.
