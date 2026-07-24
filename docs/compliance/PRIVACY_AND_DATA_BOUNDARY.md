# Privacy and confidential-data boundary

Status: design boundary; not a completed DPIA or legal opinion.

The following MUST remain off the public ledger and public repository: identity documents,
official-document numbers, names, addresses, dates of birth, beneficial-owner details, raw
KYC/KYB/PEP data, sanctions-match details, risk scores, Travel Rule payloads, source-of-funds
documents, case notes, suspicious-activity reports, non-filing decisions, and regulator
requests. The existence or subject of an SAR/STR MUST remain confidential.

The public protocol MAY carry only minimal, non-enumerable commitments, versioned policy IDs,
status references, pairwise bindings, action commitments, and audit receipts that do not reveal
that a person was screened, investigated, sanctioned, or reported.

Every confidential evidence system MUST define:

- purpose, lawful basis, data controller/processor, and jurisdiction;
- collection minimization and field-level classification;
- encryption, key custody, rotation, and break-glass access;
- role-based access, four-eyes approval, immutable access logs, and review cadence;
- retention, legal hold, deletion/crypto-erasure, backup expiry, and subject rights;
- international transfer and processor controls;
- breach detection, notification, containment, and evidence preservation; and
- non-enumerable commitment, locator, and redaction rules for public manifests.

No protocol receipt or hash may be used to reconstruct low-entropy personal facts. Public
commitments MUST be salted or otherwise non-enumerable and MUST NOT expose confidential case
state through timing, identifiers, or status transitions.
