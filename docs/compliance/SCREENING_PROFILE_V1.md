# Screening profile v1

This profile defines how a regulated transfer can require current sanctions and identity
screening without publishing personal data on ActiveChain. It is an application/provider
control whose signed result is bound to the exact chain, asset, amount, action, and selected
jurisdiction profile by P-120/P-121.

## Versioned inputs

Each profile names the authoritative list identifiers, provider, retrieval timestamp, maximum
age, matching algorithm version, normalization rules, and escalation contact. A result is invalid
when any input is missing, expired, or from an unapproved provider. Providers publish a digest of
the source snapshot; the source records and case files remain off-chain.

Provider attestations admitted by validators use `ComplianceSignatureEnvelopeV2`. Its
domain-separated signing transcript binds the exact canonical evidence commitment, provider,
subject, selected profile, chain and genesis, protocol revision, action, validity interval, and
one-shot nonce. Validators recompute the evidence commitment and consume the nonce durably before
admission returns.

`ComplianceSignatureEnvelopeV1` is archival-only because its transcript did not bind the evidence
body or complete finalized context. It has no production admission path and is never upgraded in
place. A provider must reissue legacy evidence as a freshly signed V2 attestation under a
provider-and-profile key registered for the active network and revision.

## Matching and privacy

Providers normalize names and identifiers according to the profile, apply the declared threshold,
and return only `clear`, `match`, or `inconclusive` plus a signed evidence digest. Holder identity,
raw list hits, KYC/KYB documents, and analyst notes never enter consensus state. A wallet may prove
that a current result satisfies the profile without disclosing the underlying attributes.

## Overrides and failure handling

An override requires two authorized reviewers, a reason code, expiry, and an append-only case
reference. Overrides cannot turn an expired or malformed evidence envelope into `clear`. A match
or unresolved inconclusive result fails closed for the regulated transfer; the provider may route
it to manual review. Profile revisions are new IDs and never reinterpret prior receipts.
