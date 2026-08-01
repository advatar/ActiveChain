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
