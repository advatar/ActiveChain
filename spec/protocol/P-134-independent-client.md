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

## Milestones

1. **M0 (now):** language-neutral vectors and error taxonomy are frozen.
2. **M1:** independent Go verifier accepts every positive v1.0 vector and rejects every malformed
   vector without calling Rust code.
3. **M2:** differential replay of a fixed multi-block trace matches roots, receipts, and finality.
4. **M3:** two weeks of shadow verification on Kanalen testnet with divergence telemetry.

M2 is the v1.0 launch gate. M3 is required before any non-developmental claim. The second client
is a fast-follow to the v1.0 network bootstrap, but no independent-verification decentralisation
score is awarded until M2 passes.
