# OpenWallet consent-bound issuance proof scope

Status: mechanically checked bounded model and Rust/Lean differential trace; not whole-system
certification.

`formal/lean/ActiveChain/OpenWalletConsent.lean` models the OpenWallet adapter transition system as
an abstract state machine over `Nat` identifiers and proves that credential issuance cannot bypass
the consent check, that a pre-authorized offer is refused at admission, that a spent grant nonce is
one-shot, that an approved disclosure exactly covers the request, and that every rejected operation
is a state no-op.

The production `OpenWalletAdapterV1` in `crates/wallet-core/src/openwallet.rs` independently
performs real credential registration, session admission, offer admission with the decoded-state
check, consent-digest-gated authorization, nonce-gated completion, and request-bound presentation
approval. Its observable projection — open sessions, held credentials, issuance table size split by
`IssuanceSessionState`, pending presentations, and consumed nonces — must match
`OpenWalletConsentTable.lean` byte-for-byte.

This scope exists because of [issue #678](https://github.com/advatar/ActiveChain/issues/678): a
decoded `OpenWalletCredentialOfferV1` restores its `IssuanceSessionState` from the wire, so an offer
declaring `Authorized` skipped `authorize_issuance` — the only step that verifies `consent_digest` —
and a credential could be registered with no consent check at all. The `preAuthorizedOffersAreRejected`
theorem and the `begin_issuance_pre_authorized` trace row pin that fix.

## Assumed at the production boundary

- Canonical decoding. The model takes offers, requests, and consents as already decoded,
  well-formed values. Envelope framing, length bounds, strict ascending list ordering, the
  `https://` scheme check, and enum-tag range rejection are enforced by the Rust constructors and
  codec, not proved here. The Rust half of the trace does round-trip the pre-authorized offer
  through `encode_envelope`/`decode_envelope` so that the modeled attack shape is the real one.
- Cryptographic issuer authentication. The model takes an offer as an already authenticated input
  and does not prove that only a legitimate issuer can produce one. ML-DSA signature unforgeability
  and relying-party authentication are assumed, not proved.
- Credential-content validity. A `CredentialRef` is modeled as three opaque non-zero identifiers.
  The model does not prove that the registered credential actually contains the claims the issuer
  promised, nor that its schema identifier truthfully describes it.
- Digest collision resistance. Session identifiers, grant nonces, consent digests, request
  commitments, credential identifiers, and schema identifiers are modeled as `Nat` tokens compared
  for equality. Binding therefore holds up to collision resistance of `Digest384` and of the
  canonical commitment; the model does not prove that two distinct requests cannot share a
  commitment.
- Approval-height well-formedness. `OpenWalletConsentV1` requires `approved_at <= expires_at` in its
  constructor; the approval height plays no part in `approve_presentation`, so the model omits it
  and treats constructor validity as an input precondition.
- Table ordering. Production keeps the credential, session, issuance, and consumed-nonce tables
  sorted so it can binary search them; the model appends and searches linearly. The two agree on
  membership and on every projected observable, but the model does not prove the sort itself.
- Durability, concurrency, and transport. The trace is a single sequential in-memory adapter.
  Filesystem durability, concurrent sessions, wallet-to-issuer transport, and user-interface consent
  capture are out of scope.

## Proved

- `issuanceRequiresConsent` — the headline. For any adapter state reachable by any trace of
  attempted steps, an accepted `completeIssuance` implies the session is `authorized` with the
  matching grant nonce, and that the trace contains an explicit `authorizeIssuance` step for that
  session carrying exactly the offer's consent digest. Composed from
  `completionRequiresAuthorized`, `authorizationRequiresMatchingConsent`,
  `authorizedStepIsAuthorization`, and `authorizedRequiresConsent`.
- `preAuthorizedOffersAreRejected` — an offer whose state is not `offered` is rejected by
  `beginIssuance` and the attempted step leaves the adapter unchanged. Direct regression of #678.
- `grantNonceIsOneShot` — a completed issuance records its grant nonce as consumed, the record
  survives every subsequent step, and every later state refuses both a second completion with that
  nonce and any fresh offer that replays it.
- `disclosureAnswersTheRequest` — an accepted approval implies every selected credential is held,
  every disclosed schema answers a requested schema (no over-disclosure), every requested schema is
  answered, and the consent reproduced the request commitment.
- `rejectedTransitionsPreserveState` and `rejectedTransitionsPreserveEveryTable` — a rejected
  operation is a state no-op across every adapter table.

Every theorem is fully proved; the module contains no `sorry`, no `axiom`, and no `native_decide`.
`#print axioms` reports only `propext`, `Classical.choice`, and `Quot.sound` for each headline
theorem.

Run the focused gate with:

```sh
bash scripts/check-openwallet-consent-refinement.sh
```
