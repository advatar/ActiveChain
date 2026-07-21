# Cash authorization proof scope

`formal/lean/ActiveChain/CashAuthorization.lean` models the protocol boundary that must precede
every native-cash state transition. It is dependency-free Lean 4 and is checked by `lake build`.

## Mechanically checked

- Successful admission implies exact chain, sender, canonical-intent, signature-verifier, nonce,
  height, session, and input-availability checks.
- A mismatched signed intent, wrong chain, or failed PQ signature-verifier result is rejected.
- Acceptance atomically advances the sender-local nonce and consumes the payment session, transfer
  inputs, and independent fee reserve.
- An accepted session and the exact accepted spend cannot be replayed.
- Acceptance preserves the immutable chain and sender domain of the admission lane.

## Assumptions

- `signatureVerified = true` abstracts a successful verification by the pinned ML-DSA suite. The
  model does not prove ML-DSA unforgeability or implementation correctness.
- `committedIntent = intent` represents equality after strict canonical decoding and reconstruction
  of the signing transcript. Collision resistance and codec refinement are separate obligations.
- The state represents one sender-local nonce lane. Composition across lanes requires disjoint,
  atomically committed input locks.
- Durable storage is modeled as an atomic state transition; filesystem crash refinement remains
  an implementation obligation.

## Not established by this artifact

The current Rust cash ingress does not yet refine this model: it still admits bare `CoinTransfer`
values and its legacy payment-session witness is not a keyed signature. This proof therefore fixes
the required target semantics and exposes, rather than closes, that implementation gap. Finalized
issuance/reward proof provenance, shielding, batches, paymasters, and block-level state-root binding
are also outside this artifact.
