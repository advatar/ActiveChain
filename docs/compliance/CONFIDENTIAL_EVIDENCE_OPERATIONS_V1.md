# Confidential evidence operations v1

Sensitive KYC/KYB, screening, Travel Rule, reserve, and case-management material is provider-held
evidence. ActiveChain stores only a domain-separated digest and the minimum signed result needed
for admission. A digest is not a recovery mechanism for the underlying document.

## Lifecycle

Evidence has an issuer, subject binding, audience, purpose, creation time, expiry, revocation
reference, and retention class. Providers must delete or irreversibly redact source material at
the class deadline unless a documented legal hold exists. Legal holds are off-chain case records
with an owner, reason, scope, and expiry; they do not extend an on-chain receipt.

## Access and breach

Access is least-privilege and dual-controlled for exports. Every read, correction, disclosure,
revocation, and deletion is audit-logged off-chain. A breach triggers key rotation, affected-case
assessment, regulator/customer notification according to the jurisdiction profile, and reissuance
of evidence envelopes. Previously finalized chain receipts remain immutable and continue to reveal
only their digest and declared verifier version.

## Offline verification

An offline verifier checks the canonical envelope, chain and profile commitments, signature,
freshness, and digest binding using trusted network parameters. It must not require access to the
underlying personal data and must distinguish `verified`, `expired`, `revoked`, and `unavailable`
without guessing. Missing confidential evidence never becomes a positive result.
