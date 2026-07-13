# Making Shamir-Gate the Gold Standard for What It Teaches

Shamir-Gate already has the hard parts many demos skip: exact `BigInt` arithmetic over `GF(p)`, real randomized polynomial coefficients, Lagrange interpolation, a threshold theorem test, Web Crypto AES-256-GCM, and a concrete proof view showing that `t-1` shares are compatible with multiple secrets. To make it the gold standard, I would not replace the foundation. I would sharpen the teaching path around it.

## 1. Add a guided lesson mode

Right now the app is a strong sandbox. A gold-standard teaching demo should also have a deliberate path through the material.

Add a "Lesson" or "Guided" mode that walks through:

1. Encode a secret as an integer.
2. Pick a prime field large enough to contain it.
3. Build `f(x) = secret + a1*x + ... + a(t-1)*x^(t-1) mod p`.
4. Generate shares as points on the polynomial.
5. Try fewer than `t` shares and explain why the result is not trustworthy.
6. Reconstruct with `t` shares using Lagrange interpolation at `x = 0`.
7. Split an AES key instead of the message itself.
8. Close with what SSS does not solve: bad dealers, invalid shares, lost shares, metadata, custody, and malicious participants.

This turns the demo from "here are six tabs" into a complete learning arc.

## 2. Make learners predict before revealing

The strongest teaching move would be adding small prediction checkpoints before the demo reveals outcomes.

Examples:

- "You have 2 of 3 shares. What do you expect reconstruction to produce?"
- "If the prime is smaller than the secret integer, what breaks?"
- "Do 4 of 5 shares reveal more than 3 of 5 shares?"
- "Can a malicious dealer give everyone inconsistent shares?"
- "Does Shamir protect the ciphertext, the key, or both?"

After the user answers, reveal the actual behavior and connect it to the theorem. This makes the demo teach, not merely demonstrate.

## 3. Make finite-field arithmetic visible

The current implementation correctly uses `BigInt` and modular arithmetic, but the UI could make `GF(p)` feel less like a magic phrase.

Add a compact field-workbench panel:

- Show `secret text -> UTF-8 bytes -> big-endian integer -> chosen p`.
- Show `y = f(x) mod p` for one generated share, step by step.
- Let users enter `a / b mod p` and see `a * inverse(b) mod p`.
- Show why division works only because `p` is prime.
- Show wraparound explicitly: values do not overflow; they reduce modulo `p`.

The visual polynomial tab already hints at wraparound. The gold-standard version should let learners inspect the arithmetic behind a single point.

## 4. Upgrade the security proof from static examples to an interactive proof lab

The Security Proof tab is one of the best parts of the project. Make it interactive.

Recommended changes:

- Let the user choose `t`, `p`, and the observed `t-1` shares.
- Let the user type any candidate secret `S`.
- Generate the unique degree `t-1` polynomial through `(0, S)` plus the observed shares.
- Show that every candidate secret passes the same observed shares.
- Add a small counter: "Observed shares eliminate 0 possible secrets."

That last sentence is the theorem in plain language. If users remember only one thing, make it that.

## 5. Separate three concepts that learners often confuse

The demo currently teaches all three, but a gold-standard version should explicitly keep them distinct:

- Secret sharing: split a value into threshold shares.
- Encryption: protect data with an AES key.
- Key custody: split the AES key among people or systems.

The AES Vault should state the canonical production pattern very clearly: encrypt the data normally, then secret-share the encryption key. Do not present SSS as a bulk file encryption mechanism.

## 6. Add a "threat model and limits" tab or section

The README already mentions that plain SSS is not verifiable. The UI should teach that too.

Cover these limits directly:

- Plain SSS assumes an honest dealer.
- A bad share can break reconstruction.
- Shareholders cannot verify their shares without extra protocol machinery.
- SSS does not authenticate who submitted a share.
- SSS does not protect against share copying.
- SSS does not protect metadata such as who holds shares or when reconstruction happens.
- Losing enough shares destroys recoverability.

Then show the next tools:

- VSS for dealer/share verification.
- Feldman/Pedersen commitments for verifiable shares.
- FROST for threshold signatures without reconstructing a private key in one place.
- HSM ceremonies for operational custody.

This would prevent the demo from accidentally over-teaching SSS as a complete system.

## 7. Improve share format realism

The current `x:y:p` string is good for transparency. For a gold-standard teaching tool, add a second "portable share" format that includes metadata and validation.

For example:

```text
shamir:v1
id: 2026-06-27T12:00Z-demo
t: 3
n: 5
p: 115792089237316195423570985008687907853269984665640564039457584007913129640233
x: 2
y: ...
checksum: ...
```

Teach why each field exists:

- `t` prevents reconstructing with the wrong threshold assumption.
- `p` prevents mixing field parameters.
- `id` prevents mixing shares from different splits.
- `checksum` catches transcription mistakes.
- `version` makes future format changes survivable.

Keep `x:y:p` as the math-visible format, but offer the portable format as the operational format.

## 8. Add deliberate failure cases

A great crypto demo should let users break things safely.

Add buttons or examples for:

- Duplicate x-coordinates.
- Shares from different splits.
- Wrong prime.
- One corrupted digit in a share.
- Fewer than `t` shares.
- Wrong AES IV.
- Wrong AES key share.
- Secret integer larger than `p`.

For each failure, show whether the failure is mathematical, cryptographic authentication, formatting, or operational. That classification is excellent teaching.

## 9. Add a compact glossary that is tied to the UI

Do not make this a separate wall of text. Put short definitions next to the places where the terms appear.

Terms worth defining:

- `GF(p)`
- prime field
- threshold `t`
- total shares `n`
- degree `t-1`
- constant term
- Lagrange basis polynomial
- information-theoretic security
- computational security
- authenticated encryption
- dealer
- custodian
- verifiable secret sharing

Each definition should be one sentence and connected to what the user is currently doing.

## 10. Make the polynomial visualization mathematically honest about drawing

The code correctly says the arithmetic is exact, but canvas curves over a finite field can be visually misleading because finite fields are discrete. The existing canvas connects sampled points, which is useful visually, but learners may infer a continuous real curve.

I would add a visible toggle:

- "Discrete field points" mode: show only integer x positions.
- "Connected teaching line" mode: connect points for visual continuity.

Label the connected version as an illustration, not the object itself. This is a small change with high pedagogical integrity.

## 11. Add "minimum viable math" derivations

The Lagrange stepper is already useful. Add a short derivation panel that answers:

- Why is the secret `f(0)`?
- Why does degree `t-1` require `t` points?
- Why does adding `(0, candidateSecret)` prove `t-1` shares reveal nothing?
- Why is modular inverse the finite-field version of division?

Keep these expandable. The default UI should stay interactive; the deeper math should be available when wanted.

## 12. Make assessment part of the demo

To become a teaching reference, add an optional final challenge:

"You are designing a 3-of-5 recovery scheme for an AES key. Configure the system, generate shares, corrupt one share, explain the failure, then recover with three valid shares."

The app can check whether the learner succeeds and summarize what they demonstrated:

- Chose `t` and `n` correctly.
- Generated a key and ciphertext.
- Rejected bad reconstruction.
- Reconstructed with valid shares.
- Explained why two shares were insufficient.

This makes the demo useful in a classroom, workshop, or self-study setting.

## 13. Add citations and standards links in the UI

The README names Shamir and RFC 9591. The app should expose a small "Sources" panel:

- Adi Shamir, "How to Share a Secret", Communications of the ACM, 1979.
- RFC 9591, FROST threshold signatures.
- NIST SP 800-38D for AES-GCM.
- References for Feldman/Pedersen VSS.

This makes the demo feel authoritative and gives serious learners a path forward.

## 14. Improve accessibility for the math visuals

The app already uses ARIA labels, keyboard tabs, status regions, skip links, and reduced-motion handling. The next gold-standard step is making the visual math non-visual too.

Add text alternatives that update with the canvas:

- Current polynomial coefficients.
- Selected shares.
- Whether the threshold is met.
- Reconstructed secret or candidate secrets.
- A table of plotted points for the selected shares.

This helps screen-reader users and also helps sighted learners who process tables better than graphics.

## 15. Strengthen tests around teaching claims

The current tests cover the cryptographic core well. Add tests for the claims the UI teaches:

- Generated share metadata uses the threshold from generation time, even if sliders change later.
- Duplicate x-coordinates are rejected.
- Shares with different primes are rejected in both Gate and AES flows.
- Portable share parsing rejects mixed split IDs.
- Corrupted AES share fails authentication rather than producing a false plaintext.
- For `t-1` observed shares, several candidate secrets produce valid consistent polynomials.

This keeps the teaching content and code behavior aligned.

## 16. Add a production-readiness disclaimer without weakening the demo

Use direct language:

"This demo implements the math of Shamir Secret Sharing and uses real browser cryptography for AES-GCM. It is not a complete custody product. Production systems need authenticated share formats, identity, audit logs, secure storage, ceremonies, backups, verifiable shares, and incident procedures."

That sentence protects learners from misusing the demo while preserving confidence in the math.

## Suggested priority order

If I were improving this in stages, I would do it in this order:

1. Guided lesson mode.
2. Interactive `t-1` proof lab.
3. Field arithmetic workbench.
4. Threat model and limits section.
5. Portable share format with split ID and checksum.
6. Deliberate failure cases.
7. Discrete-vs-connected polynomial visualization toggle.
8. Accessibility text alternatives for the canvas views.
9. UI-linked glossary and citations.
10. Final learner challenge.

## Bottom line

The demo is already unusually strong because it teaches the real theorem instead of only showing a happy-path split and reconstruct. The path to gold standard is to make the learner do more of the thinking: predict outcomes, inspect one share mathematically, try invalid inputs, prove to themselves that `t-1` shares eliminate no candidate secrets, and leave with a clear boundary between Shamir math and production key-custody systems.