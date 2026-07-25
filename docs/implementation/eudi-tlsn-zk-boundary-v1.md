# EUDI/TLSNotary to ZK predicate boundary v1

EU Wallet or TLSNotary components may issue a credential, but ActiveChain verifies only a bounded
predicate proof. The proof commits to issuer, schema, status source, issuance/expiry, holder key,
audience, action, chain, and nonce. It reveals the predicate result—not the underlying identity,
nationality, document, or source transcript.

Accepted predicates include threshold and set-membership claims such as `over_18`, `not_us`,
`not_north_korea`, residency eligibility, and reserve/funds thresholds. A verifier rejects proofs
with an unknown issuer/schema, stale or revoked status, wrong holder/audience/action, replayed
nonce, wrong chain, or a predicate outside the selected jurisdiction profile.

Credential storage, revocation details, and TLSNotary transcripts remain off-chain. The chain stores
only the canonical predicate commitment and the signed admission result, which can be verified
offline using trusted issuer and network manifests.
