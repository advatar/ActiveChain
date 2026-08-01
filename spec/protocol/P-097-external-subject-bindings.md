# P-097: External credential subject bindings

## 1. Identity separation

An EUDI credential holder/device key and an ActiveChain `PrincipalId` are distinct identities.
`ExternalSubjectBindingV1` is the wallet-authorized association transcript between them. A wallet
MUST display and approve the exact issuer binding, schema, principal, purpose, audience, scope,
expiry, consequences, and holder/device key commitments. Routing a request is not approval.

## 2. Profiles

- **Account:** binds the principal and holder key without a presentation scope.
- **Pairwise:** additionally binds exactly one verifier, purpose, or asset scope. Different scopes
  produce different subject commitments.
- **Private proof:** replaces the public holder-key input with a secret witness commitment and
  requires an explicit scope.
- **Device:** binds the principal, holder key, and nonzero device/key-attestation commitment.

Profiles are closed and structurally disjoint. Pairwise/private evidence cannot validate as
account-bound evidence, and device evidence cannot omit its attestation.

## 3. Derivation and replay

The subject digest uses SHAKE256 domain `ACTIVECHAIN-EXTERNAL-SUBJECT-BINDING-V1` and
four-byte-big-endian length prefixes over selected chain, genesis, issuer binding, schema,
principal, holder/private witness, profile, scope, device attestation, and version fields. The
complete approval transcript has a separate association commitment and replay key. Wallets MUST
durably consume replay keys.

## 4. Rotation, recovery, and migration

Sequence 1 has no previous commitment. A successor increments sequence and binding version,
commits the exact previous transcript, advances issuance height, uses a fresh nonce and wallet
authorization, and preserves chain, genesis, issuer, schema, principal, profile, and scope. Holder
and device commitments may rotate. A new pairwise scope is a separate sequence-1 association.

## 5. Privacy limits

Pairwise derivation prevents equality correlation across distinct scopes assuming holder/private
witness commitments have sufficient entropy and remain protected. It does not prevent inference
from rare predicates, repeated queries, colluding verifiers, network metadata, or wallet
disclosure. Wallet consent MUST surface those risks. Raw keys, credentials, and personal
attributes remain off-chain.
