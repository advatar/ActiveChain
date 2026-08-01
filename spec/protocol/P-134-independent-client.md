# P-134 — Independent v1 client conformance budget

Status: normative release gate.

ActiveChain will not claim independent verification until a second implementation can verify the
same v1.0 state transitions without importing the Rust transition function or linking Rust
consensus code.

## v1.0 conformance surface

The funded second-client target is the verifier surface, not a second wallet or every operator
tool. It must implement these bounded modules:

| Module | Required conformance evidence |
|---|---|
| canonical codec | envelope, bounds, trailing-data, unknown-tag vectors |
| principals/credentials/capabilities | positive and malformed authorization vectors |
| APL/ObjectVM subset | deterministic transition and rejection vectors |
| public cash lane | Coin Cell conservation, membership and receipt vectors |
| consensus finality | PQ signature, quorum, epoch and chain-prefix vectors |
| light-client proof path | finalized header, DA sample and proof-binding vectors |
| migration/version dispatch | v1 rejection of reserved/future tags and replay vectors |

The target surface is intentionally limited to the v1.0 mandatory set in P-131. Private payments,
consensus-required validity proofs, protected ordering, compute jobs, and bridges are separate
version milestones and MUST NOT block the first v1.0 verifier release.

## Machine-counted complexity budget

`testing/independent-client-budget-v1.tsv` is checked against the canonical type registry in CI.
At the current frozen registry it yields this cumulative budget:

| Version | Active canonical identities | Newly active | Incremental estimate |
|---|---:|---:|---:|
| v1.0 | 171 | 171 | 20–30 engineer-months |
| v1.1 | 171 | 0 | 6–10 engineer-months for mandatory-proof semantics |
| v1.2 | 183 | 12 | 12–18 engineer-months |
| v1.3 | 197 | 14 | 8–12 engineer-months |
| v1.4 | 200 | 3 | 6–10 engineer-months |
| v2 | 200 currently assigned | 0 currently assigned | 12–24 engineer-months, provisional |

The identity count is not a proxy for implementation difficulty: v1.1 changes proof admission
semantics without activating another currently registered envelope. Estimates include independent
codec and cryptographic work, negative vectors, differential tests, review, and documentation;
they exclude wallets, explorer UI, and operator tooling. The current corpus has 26 v1-named files
and 787 non-header fixture rows, but most are not yet language-neutral semantic vectors and MUST
NOT be counted as M1 coverage merely because a TSV reader can parse them.

The launch allocation is three Go/security engineers for eight to ten months, plus a half-time
cryptography reviewer and half-time conformance/QA owner. This is a required launch allocation,
not evidence that hiring or funding has occurred; an owner, budget, and delivery calendar must be
linked before M1 starts.

## Milestones

1. **M0 (now):** the vector inventory, file-shape reader, and draft error taxonomy exist; semantic
   vectors are not yet frozen.
2. **M1:** independent Go verifier accepts every positive v1.0 vector and rejects every malformed
   vector without calling Rust code.
3. **M2:** differential replay of a fixed multi-block trace matches roots, receipts, and finality.
4. **M3:** two weeks of shadow verification on Kanalen testnet with divergence telemetry.

The checked-in Go program is currently **M0 only**: it validates vector-file structure and
independence metadata, but does not decode protocol envelopes, verify ML-DSA, replay cash or state,
or compare finality roots. Its success is not M1 or M2 evidence.

M2 is the public v1.0 testnet launch gate. A Rust-only bootstrap may run solely as a labelled
development network; it is not the “live and verified testnet.” M3 is required before any
non-developmental claim. No independent-verification decentralisation score is awarded until M2
passes.
