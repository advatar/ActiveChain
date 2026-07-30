# Regulated-profile implementation plan

This plan is derived from the auditor-assurance priorities supplied on 2026-07-24.
The referenced `AUDITOR_ASSURANCE_PROTOCOL.md` was not present in the active checkout;
the supplied eight-point priority list is therefore the current planning authority.

## Boundary and release rule

ActiveChain must not claim “audited”, “AML compliant”, or “regulator approved” until
operating evidence and an independent security/compliance engagement exist. Protocol
code may provide deterministic commitments, authorization, evidence binding, and
privacy-preserving proofs; it cannot decide the legal status of an operator or service.

## Workstreams and dependency order

## Auditor protocol alignment

The implementation must be auditable as separate modules, not as a single “ActiveChain
compliance” claim: `CORE`, `IDENTITY`, `REGULATED-TRANSFER`, `FINANCIAL-CRIME-OPS`,
`ASSET-ISSUER`, `BRIDGE-PAYMENT`, `WALLET-CUSTODY`, and `OPERATIONS`. Each module gets an
explicit Applicable/Not applicable/Not examined decision and a separate conclusion.

Evidence and release gates use the protocol's stages: S0 documentation, S1 design and
implementation, S2 independently reproduced testing, and S3 operating effectiveness.
Evidence must be classified E0 through E5, with E4 auditor-controlled reproduction and E5
operating-period populations, samples, reconciliations, and owner records. A new regulated
profile should plan for at least a 90-day observation period before an S3 opinion.

The audit freeze must capture the full commit and signed tag, source/Cargo/lock hashes,
toolchain and formal-method versions, container/SBOM and binary hashes, chain/genesis and
validator/RPC configuration, policy and issuer-registry revisions, screening-provider
versions, Travel Rule profile, and observation period. Links to a moving branch are not audit
evidence.

### 0. Evidence inventory and ownership (before implementation)

- Assign an accountable owner and evidence repository for every control.
- Create a signed role-and-jurisdiction matrix covering developer, validator operators,
  hosted RPC/indexers, custodians, issuers, bridges, CASPs, control holders, vendors,
  and countries of operation.
- Record effective dates, legal entity, service boundary, data controller/processor role,
  escalation owner, and evidence expiry for each row.
- Gate: matrix is signed by accountable control holders; unsigned rows remain out of scope.
- Establish the evidence-manifest schema, confidentiality classes, immutable hashes, retention
  locations, and chain-of-custody owners before collecting samples.

### 1. Compliance boundary and control taxonomy

Publish a versioned control matrix classifying each requirement as:

- consensus-enforced;
- application/wallet-enforced;
- provider-operated;
- manually operated; or
- explicitly outside scope.

For every control define input, decision, authority, failure mode, override authority,
audit evidence, retention, and whether the decision is public, selectively disclosed,
or strictly off-chain.

### 2. Identity, KYC/KYB, and credential governance

- Freeze accepted issuer registry, credential schemas, assurance levels, proof predicates,
  freshness windows, revocation/status mechanisms, and failure behavior.
- Define EUDI/OpenID4VCI/OpenID4VP and mdoc/VC interoperability profiles.
- Bind only minimal commitments/predicates to actions; never put KYC payloads on-chain.
- Require pairwise identifiers/nullifiers, consent receipts, deletion workflows, and issuer
  suspension/revocation handling.
- Gate: positive, malformed, stale, revoked, wrong-audience, and issuer-substitution vectors.

### 3. Sanctions and screening profile

Version and freeze:

- authoritative lists and jurisdictional coverage;
- ingestion and refresh SLAs;
- transliteration, fuzzy-match, and threshold parameters;
- address and transaction analytics sources;
- manual-review, override, freeze, release, and escalation authority;
- immutable off-chain audit trail and evidence retention.

Consensus should bind only the resulting policy decision/commitment and version—not raw
screening data or analyst notes.

### 4. Travel Rule profile

Define a secure off-chain message profile cryptographically bound to:

`chain_id, protocol_revision, transaction_id, asset_id, amount, originator, beneficiary,
policy_version, counterparty, acknowledgement, and message expiry`.

Specify encryption, key discovery/rotation, counterparty authentication, retries, duplicate
handling, refusal/timeout behavior, correction, deletion, and evidence export. Add vectors for
substitution, replay, wrong-chain, wrong-asset, amount mismatch, and acknowledgement forgery.

### 5. Transaction monitoring and case management

- Define monitored population, event joins, risk rules, thresholds, typologies, and alert SLAs.
- Specify case lifecycle, analyst roles, four-eyes approval, escalation, freeze/release actions,
  evidence chain, and tamper-evident case exports.
- Define population reconciliation: every finalized value-bearing action must be accounted for
  as monitored, exempt-with-reason, pending, or failed.
- Document FIU-reporting procedures per jurisdiction; keep reports and SAR/STR content off-chain.

### 6. Privacy, retention, deletion, and breach controls

- Keep KYC, Travel Rule, sanctions, and suspicious-activity records in segregated encrypted
  stores, never public state.
- Define purpose limitation, retention schedules, legal holds, deletion/crypto-erasure,
  subject access, privileged access, break-glass access, and breach notification.
- Bind public commitments to an evidence locator/version without exposing the evidence itself.
- Test data minimization, redaction, deletion, backup expiry, and access-log integrity.
- Maintain a public commitment/manifest only; confidential annexes must remain access-controlled
  and must not reveal that a person was screened, investigated, sanctioned, or reported.

### 7. Implementation and formal-verification gates

Implement shared primitives only after the profiles above are frozen:

- versioned `CompliancePolicyId`, `IssuerRegistrySnapshot`, `ScreeningDecisionCommitment`,
  `TravelRuleEnvelope`, `MonitoringCaseReference`, and `EvidenceLocator` types;
- exact-chain/asset/amount binding helpers;
- durable replay/idempotency barriers and terminal case transitions;
- wallet/RPC surfaces exposing status without sensitive payloads;
- Lean/TLA+/property tests for no provenance escalation, no policy bypass, exact population
  reconciliation, terminal immutability, replay resistance, and privacy-boundary preservation.

### 8. Operating evidence and independent engagement

- Run a time-bounded pilot with real operational logs, incidents, reconciliations, access
  reviews, key rotations, screening refreshes, and case outcomes.
- Preserve signed evidence packages and control-owner attestations.
- Commission independent security, privacy, AML/CFT, sanctions, Travel Rule, and jurisdictional
  reviews; track findings to closure.
- Only then decide whether a regulated-profile deployment is legally supportable in each country.

The auditor must independently select samples. The following populations require 100% review:
confirmed/unresolved sanctions matches and overrides, high-risk suspicious-activity decisions,
material fraud or key incidents, privileged/emergency changes, issuer exceptions and reserve
breaks, Critical/High findings, repeated Travel Rule failures, and senior-management overrides.

## Immediate execution sequence

1. Create the signed role/jurisdiction matrix and compliance-boundary document.
2. Freeze credential, sanctions, Travel Rule, and monitoring schemas as separate versioned specs.
3. Implement off-chain evidence stores and commitment/reference types.
4. Add deterministic vectors and formal boundary proofs.
5. Build operator consoles for screening, cases, reconciliation, and evidence export.
6. Run a controlled pilot and collect operating-period evidence.
7. Seek regulated-profile opinion and independent engagement using the evidence package.

## Required repository artifacts

The following paths are the implementation targets from the protocol (public specifications
must not contain provider secrets, personal data, match details, case notes, or reporting data):

```text
docs/compliance/ROLE_JURISDICTION_MATRIX.md
docs/compliance/COMPLIANCE_BOUNDARY.md
docs/compliance/REGULATORY_CHANGE_LOG.md
docs/compliance/PRIVACY_AND_DATA_BOUNDARY.md
docs/compliance/TRAVEL_RULE_PROFILE.md
docs/compliance/SCREENING_PROFILE_V1.md
docs/compliance/TRANSACTION_MONITORING_CONTROL_SPEC.md
docs/compliance/ASSET_ISSUER_CONTROL_PROFILE.md
spec/protocol/P-120-compliance-evidence.md
spec/protocol/P-121-regulated-transfer-binding.md
testing/vectors/compliance/
testing/vectors/travel-rule/
testing/vectors/sanctions/
testing/vectors/issuer-controls/
scripts/check-compliance-vectors.sh
audit/evidence-manifest.json
audit/reports/
audit/remediation/
```

The first implementation artifacts should be the role matrix, compliance boundary, regulatory
change log, privacy/data boundary, and evidence-manifest template. Protocol types should follow
only after the policy profiles and legal assumptions are frozen.

## Non-goals until the gates pass

- No public KYC data, sanctions lists, Travel Rule payloads, or SAR/STR content on-chain.
- No automatic claim that a credential equals legal KYC/KYB approval.
- No “AML compliant”, “audited”, or “regulator approved” product language.
- No production value enablement based solely on protocol proofs or testnet behavior.
