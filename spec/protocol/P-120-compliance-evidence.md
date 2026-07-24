# P-120: Compliance evidence envelope

- Status: Draft 0.1
- Protocol version: Development

P-120 defines the minimum, privacy-preserving evidence needed for a regulated application to
bind an off-chain control decision to one exact ActiveChain action. It does not perform KYC,
sanctions screening, monitoring, or legal classification. Those remain accountable off-chain
controls.

## Envelope

`ComplianceEvidenceEnvelopeV1` (`0x00d0`, revision 1) contains:

```text
profile_id, profile_revision, chain_id, genesis_commitment,
operator_principal, subject_pairwise_binding,
credential_fact_commitments, issuer_status_commitments,
screening_assurance_class, screening_policy_commitment,
screened_at, valid_until, travel_rule_commitment,
self_hosted_control_commitment, action_intent_commitment,
purpose, audience, nonce, verifier_principal, verifier_signature
```

All identifiers and commitments are fixed-width canonical values. Lists are length-bounded and
strictly sorted. `valid_until` must not precede `screened_at`; `nonce` is single-use within the
profile and operator scope. The envelope is rejected for wrong chain/genesis, expired evidence,
empty required commitments, duplicate list entries, unknown revisions, trailing bytes, or a
signature that does not cover the complete canonical envelope.

The envelope MUST NOT contain names, dates of birth, addresses, document numbers, beneficial
owners, raw sanctions results, risk scores, case state, source-of-funds documents, or SAR/STR
data. A positive result means only that named controls were executed under the named profile for
the exact action before expiry.

## Policy composition

Authorization is an intersection of authenticated actor, attenuated authority, current required
credential facts, current screening evidence, applicable Travel Rule binding, APL permit, and no
profile/protocol forbid. Evidence failure is fail-closed and must not reveal the confidential
reason through public state.
