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

- Distributing a secret across multiple custodians with a threshold requirement
- Understanding why FROST, MPC, and HSM key ceremonies work
- Teaching the difference between computational security (RSA, AES) and
  information-theoretic security (Shamir — secure even against infinite compute)
- Splitting an AES-256 key across administrators for high-assurance systems

## Live Demo

https://systemslibrarian.github.io/crypto-lab-shamir-gate/

## How to Run Locally

```
git clone https://github.com/systemslibrarian/crypto-lab-shamir-gate
cd crypto-lab-shamir-gate/demos/shamir-gate
npm install
npm run dev
```

## Part of the Crypto-Lab Suite

One of 70+ browser demos at systemslibrarian.github.io/crypto-lab/ — spanning
Atbash (~600 BCE) through NIST FIPS 203/204/205 (2024). Shamir (1979) sits in
the secret-sharing tier alongside crypto-lab-frost-threshold, crypto-lab-vss-gate,
and crypto-lab-silent-tally.
