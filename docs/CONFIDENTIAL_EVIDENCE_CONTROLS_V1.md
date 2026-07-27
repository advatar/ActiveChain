# Confidential evidence controls v1

KYC/KYB documents, Travel Rule payloads, screening matches, suspicious-activity records, and
execution files are confidential provider data. They are never written to consensus state.

## Lifecycle

- Each evidence item has a provider-local identifier, class, jurisdiction, purpose, access policy,
  retention deadline, and cryptographic commitment.
- Access is least-privilege, authenticated, logged, and purpose-bound. Chain proofs reveal only the
  commitment and the minimum admission result.
- Deletion or legal hold changes provider state and emits a new signed audit commitment; it does
  not erase finalized chain history or reveal the underlying content.
- Breach response records scope, time, containment, notification decision, and remediation as
  commitments. Secrets and raw evidence are rotated/revoked off-chain.
- Offline verification uses trusted network parameters and the commitment, without requiring
  access to confidential data unless an authorized disclosure workflow is invoked.

Retention, deletion, and disclosure policies are versioned by jurisdiction and evidence class.
Ambiguous policy selection is a manual-review state and cannot silently choose a permissive policy.
