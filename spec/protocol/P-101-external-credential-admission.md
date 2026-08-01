# P-101: External credential fact admission

## 1. Construction boundary

`VerifiedExternalPresentation` is an opaque, non-canonical adapter result with no production
constructor or decoder. Only registered SD-JWT VC and mdoc verification functions create it.
`VcIssuerPresentationV1` remains caller-decodable evidence content and MUST NOT directly create a
P-021 verified fact.

## 2. Admission policy

External admission uses closed, sorted allowlists for issuer, credential configuration, and
canonical schema. It additionally checks minimum assurance without upgrading the source format,
maximum finalized status age, required issuance-log evidence, exact subject association, purpose,
verifier version, proof version, policy revision, and the adapter replay nullifier.

Failure returns only a typed code and commitments to policy, issuer authorization, status snapshot,
and replay nullifier. Receipts contain no credential bytes, subject identifiers, claim names, or
claim values. An optional ML-DSA companion remains a separately issued native credential and cannot
alter the external evidence's format or assurance.

## 3. P-023 composition

Successful admission creates a private-constructor `VerifiedExternalCredentialFact`.
`inject_external_schema_facts` extracts only its schema commitment, canonicalizes the bounded fact
set, and preserves all actor, action, resource, value, purpose, capability, approval, and lifecycle
fields produced by their independent verifiers. External identity facts are never capabilities or
ambient authority. Normal default-deny, forbid precedence, limits, and atomic obligations continue
to apply unchanged.
