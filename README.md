# crypto-lab-shamir-gate

## What It Is

Browser-based Shamir's Secret Sharing demo covering the complete protocol:
polynomial construction over GF(p), Lagrange interpolation with step-by-step
visualization, information-theoretic security proof (t-1 shares reveal zero
information), AES-256-GCM encryption with split key, and real-world deployments
in HSMs, FROST threshold signatures, and CA key ceremonies.

All arithmetic uses BigInt over a prime field. No floating point approximations.
The polynomial visualization shows what under-threshold shares actually mean —
multiple valid polynomials consistent with the same shares, each reaching a
different secret — making the security guarantee tangible rather than abstract.

## When to Use It

- Distributing a secret across multiple custodians with a threshold requirement.
- Understanding why FROST, MPC, and HSM key ceremonies work.
- Teaching the difference between computational security (RSA, AES) and
  information-theoretic security (Shamir — secure even against infinite compute).
- Splitting an AES-256 key across administrators for high-assurance systems.
- Do NOT use this as production key-management software — it is a teaching demo, not a hardened secret-sharing library or HSM.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-shamir-gate](https://systemslibrarian.github.io/crypto-lab-shamir-gate/)**

Build a `t`-of-`n` split over a prime field, watch the polynomial and Lagrange interpolation reconstruct the secret from any `t` shares, and see why `t-1` shares reveal nothing — the visualizer shows multiple polynomials consistent with the same under-threshold shares, each pointing to a different secret. A worked example also splits an AES-256 key and re-encrypts once enough shares are combined.

## What Can Go Wrong

- **Duplicate or reused share coordinates** — every share must sit at a distinct, non-zero evaluation point `x`; reusing an `x` (or leaking the secret's point `x=0`) breaks reconstruction or the secret outright.
- **Wrong field** — a non-prime modulus, or a field smaller than the secret, voids the information-theoretic guarantee; arithmetic must be exact over GF(p), never floating point.
- **No verifiability in plain Shamir** — a malicious dealer can hand out inconsistent shares and a shareholder can submit a forged one, with no way for honest parties to detect it. That is exactly what Verifiable Secret Sharing (Feldman/Pedersen VSS) adds.
- **The reconstruction point is a single point of compromise** — the full secret briefly exists in one place when shares are combined; that host/moment must be protected.
- **Weak coefficient randomness** — the polynomial's non-constant coefficients must be uniformly random in the field; predictable coefficients leak information about the secret.

## Real-World Usage

- **HSM and CA root-key ceremonies** — `M`-of-`N` custodians hold shares of a master/root key (e.g., the DNSSEC root KSK ceremony).
- **Threshold signatures and MPC wallets** — FROST, GG20, and custody platforms split signing keys so no single party can sign alone.
- **HashiCorp Vault unseal keys** — Vault uses Shamir to split its master key across operators by default.
- **Key escrow, backup, and recovery** — high-assurance systems shard a secret so recovery needs a quorum, not any one administrator.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-shamir-gate
cd crypto-lab-shamir-gate/demos/shamir-gate
npm install
npm run dev
```

## Related Demos

- [crypto-lab-vss-gate](https://systemslibrarian.github.io/crypto-lab-vss-gate/) — Verifiable Secret Sharing (Feldman), which adds the cheating-detection Shamir lacks.
- [crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/) — FROST threshold Schnorr signatures built on secret-shared keys.
- [crypto-lab-threshold-decrypt](https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/) — threshold decryption where a quorum cooperates to open a ciphertext.
- [crypto-lab-silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) — secret-sharing applied to private aggregation/voting.
- [crypto-lab-threshold-mldsa](https://systemslibrarian.github.io/crypto-lab-threshold-mldsa/) — distributed post-quantum signing from shared key material.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
