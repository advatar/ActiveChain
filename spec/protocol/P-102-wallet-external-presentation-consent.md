# P-102: Wallet external presentation consent

## 1. Wallet-owned approval

Deep links and App Intents route requests but never approve them. Before user presence, the wallet
commits and displays verified requester, issuer/profile, intended principal, chain,
resource/asset/action, purpose, audience, exact disclosures or predicates, assurance, retention,
policy revision, nonce, expiry, linkability warning, value/fees, and resulting capability-gated
action. Localized labels are presentation aids; canonical commitments are signed.

## 2. State machine

`ExternalPresentationConsentCoordinatorV1` begins a bounded session only for a fresh nonce and
unexpired request. Approval requires the exact displayed commitment, exact minimal disclosure set,
and nonzero platform user-presence evidence. Changed requests, over-disclosure, user-presence
failure, timeout, cancellation, replay, and unknown sessions emit no authorization.

The one-shot authorization contains commitments only and permits the platform custody layer to
sign the already constrained presentation. It never exports or accepts raw private keys.

## 3. Audit, recovery, and privacy

Audit records retain session/display commitments, assurance, outcome, and time—not claims,
credentials, subject identifiers, keys, or verifier-supplied labels. State commitments cover the
monotonic generation, consumed nonces, and audit records. Restore or device migration must meet the
minimum known generation and exact checkpoint commitment; rollback fails closed. Association
rotation and migration continue through P-097's exact-predecessor wallet authorization.

## 4. Platform integration

EUWallet issue 128 and its merged implementation add the same separately tagged ActiveChain
context to the wallet-owned OpenID4VP consent hash while preserving ordinary EUDI presentations as
a distinct profile. Platform shells perform biometric/user-presence checks and receive only
canonical commitments across FFI.

## 5. Production OpenID4VP transport

Both wallet- and verifier-initiated links create review state only. The accepted deep-link form is
`openid4vp://authorize` with one HTTPS `request_uri`; embedded `redirect_uri` or `response_uri`,
userinfo, fragments, duplicate parameters, HTTP, and alternate schemes fail closed. Response
delivery uses the response URI and encryption-key commitments from pinned verifier metadata; a
redirect can never replace either value.

`OpenId4VpTransportSnapshotV1` durably records review, approval, post, callback consumption and
cancelled terminal state plus sorted consumed nonces. Publication must persist the next snapshot
before acknowledging a post or callback. Restart restores the exact generation and preserves
one-shot behavior.

Live resolution accepts only exact verifier metadata, issuer/profile binding, chain/genesis, trust
revision, monotonic status sequence, finalized height and validity window. Unknown, stale, rolled
back or revoked sources fail closed. A successful response carries commitments to the existing
bounded adapter output and receipt; JSON, CBOR, COSE/X.509, disclosures and raw credentials remain
outside consensus and the persistent transport snapshot.
