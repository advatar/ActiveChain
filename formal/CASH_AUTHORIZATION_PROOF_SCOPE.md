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

`crates/wallet-core/src/cash_authorization.rs` and `TransactionIngress` now implement the modeled
admission transition for the in-memory reference ledger:

| Lean model value or predicate | Rust refinement |
| --- | --- |
| `Intent.chainId` | `CashAuthorizationRequestV1::chain_id`, checked against the immutable `GenesisEconomy` chain ID |
| `Intent.sender` and `Witness.signer` | the `CoinTransfer` sender and request signer, required to match a finalized sender-to-key registration |
| `Witness.committedIntent = intent` | ML-DSA signs a domain-separated, length-bound, strict canonical request envelope; the intent ID is recomputed from that transcript and is not accepted from the caller |
| `Witness.signatureVerified` | `AuthorizedCashTransferV1::verify` using the exact ML-DSA-44 public key registered for the sender |
| `Intent.nonce = State.nextNonce` | exact per-sender `u64` nonce equality followed by checked increment |
| `height <= validUntil` | checks against both the transfer validity height and the no-longer-than-transfer payment-session expiry |
| recipient binding | the carried recipient commitment is recomputed from the actual `CoinTransfer.recipient` during strict decode and checked again at admission |
| fresh session | a sender-local consumed-session set, updated only after the ledger transition succeeds |
| `InputsAvailable` | an ingress input barrier plus the Coin Cell ledger's live-cell and ownership checks, covering all inputs and the independent fee reserve |
| atomic `apply` | the transfer is evaluated against a cloned ledger; the ledger, next nonce, session, and input barriers become visible together only after all ledger invariants succeed |

The authoritative network method `TransactionIngress::submit_envelope` accepts only canonical
`AuthorizedCashTransferV1` (type `0x008b`, schema version 1). A bare `CoinTransfer`, wrong type or
version, malformed length, and trailing bytes fail strict decode. The old direct transition helper
is retained only as `submit_bare_non_authoritative_for_testing`; no network handler calls it.

Unit tests exercise valid authorization and rejection of bare, tampered, wrong-version,
trailing-byte, wrong-chain, wrong-sender, wrong-key, wrong-nonce, expired, replayed-session, and
replayed-input requests. They also establish that a failed ledger transition consumes none of the
nonce, session, or input barriers.

## Remaining refinement obligations

- Sender-to-key registration is an explicit input to the wallet ingress. The identity/authority
  layer must supply it only from a finalized principal-controller record and must define
  consensus-authorized rotation and recovery.
- The in-memory atomic transition has no crash-durable journal yet. Validator integration must
  persist the ledger and authorization barriers in the same atomic snapshot before acknowledging
  admission.
- `&mut TransactionIngress` serializes one process. Multi-process execution still needs the
  protocol input-lock/commit boundary proved against concurrent lanes.
- The legacy `PaymentSession` and `AuthorizationWitness` helpers remain wallet-policy POC APIs;
  they are not accepted by network ingress and do not satisfy this authorization proof by
  themselves.
- Finalized issuance/reward proof provenance, shielding, batches, paymasters, and block-level
  state-root/finality binding remain outside this artifact.
