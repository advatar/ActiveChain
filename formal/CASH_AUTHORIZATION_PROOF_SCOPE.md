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

## Rust refinement boundary

`crates/wallet-core/src/cash_authorization.rs`, `cash_persistence.rs`, and `TransactionIngress`
implement the modeled admission transition and its crash-durable publication boundary:

| Lean model value or predicate | Rust refinement |
| --- | --- |
| `Intent.chainId` | `CashAuthorizationRequestV1::chain_id`, checked against the immutable `GenesisEconomy` chain ID |
| `Intent.sender` and `Witness.signer` | the `CoinTransfer` sender and request signer, required to match a finalized principal plus active ML-DSA-44 session authenticator; a consensus/light-client verifier must accept the principal against the named finalized state root |
| `Witness.committedIntent = intent` | ML-DSA signs a domain-separated, length-bound, strict canonical request envelope; the intent ID is recomputed from that transcript and is not accepted from the caller |
| `Witness.signatureVerified` | `AuthorizedCashTransferV1::verify` using the exact ML-DSA-44 public key registered for the sender |
| `Intent.nonce = State.nextNonce` | exact per-sender `u64` nonce equality followed by checked increment |
| `height <= validUntil` | checks against both the transfer validity height and the no-longer-than-transfer payment-session expiry |
| recipient binding | the carried recipient commitment is recomputed from the actual `CoinTransfer.recipient` during strict decode and checked again at admission |
| fresh session | a sender-local consumed-session set, updated only after the ledger transition succeeds |
| `InputsAvailable` | an ingress input barrier plus the Coin Cell ledger's live-cell and ownership checks, covering all inputs and the independent fee reserve |
| atomic `apply` | the transfer is evaluated against a cloned ingress; ledger, finalized key provenance, nonce, session, and input barriers are canonically encoded, fsynced to a temporary file, renamed, and parent-directory fsynced before the clone becomes visible or the network receives success |

The authoritative network method `TransactionIngress::submit_envelope` accepts only canonical
`AuthorizedCashTransferV1` (type `0x008b`, schema version 1). A bare `CoinTransfer`, wrong type or
version, malformed length, and trailing bytes fail strict decode. The old direct transition helper
is retained only as `submit_bare_non_authoritative_for_testing`; no network handler calls it.

Unit tests exercise valid authorization and rejection of bare, tampered, wrong-version,
trailing-byte, wrong-chain, wrong-sender, wrong-key, wrong-nonce, expired, replayed-session, and
replayed-input requests. They also establish that failed ledger or snapshot publication consumes
none of the nonce, session, input, or ledger state; restart preserves all barriers; corrupt and
wrong-chain snapshots fail closed; and key rotation requires a newer finalized principal sequence.

## Remaining refinement obligations

- `FinalizedIdentityKeyVerifier` is the explicit consensus/light-client refinement boundary. Its
  implementation must verify principal membership and finality for the supplied state root; this
  artifact tests that rejection propagates but does not prove the external finality verifier.
- Cash schema v1 deliberately accepts one active session authenticator and commits that singleton
  set into `Principal.authenticator_set_root`; multipurpose/multikey authenticator-set membership is
  deferred to the canonical DID/authenticator-set phase.
- `&mut TransactionIngress` serializes one process. Multi-process execution still needs the
  protocol input-lock/commit boundary proved against concurrent lanes.
- The legacy `PaymentSession` and `AuthorizationWitness` helpers remain wallet-policy POC APIs;
  they are not accepted by network ingress and do not satisfy this authorization proof by
  themselves.
- Finalized issuance/reward proof provenance, shielding, batches, paymasters, and block-level
  state-root/finality binding remain outside this artifact.
