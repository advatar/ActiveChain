# P-121: Regulated-transfer binding

- Status: Draft 0.1
- Protocol version: Development

P-121 binds a regulated transfer to private compliance evidence and an encrypted Travel Rule
exchange without publishing personal data.

## Travel Rule binding

`TravelRuleBindingV1` (`0x00d1`, revision 1) contains the message profile/version, originator
and beneficiary CASP principals, encrypted-message commitment, exact transfer-intent commitment,
chain ID and genesis commitment, asset ID, amount, expiry, acknowledgement commitment, single-use
identifier, and sender/receiver signatures.

The encrypted payload travels over an authenticated off-chain channel. Chain-visible outcomes are
only `requested`, `accepted`, `rejected`, `returned`, `suspended`, or `expired`; personal fields
and confidential reasons remain off-chain. The binding is invalid if chain, asset, amount,
intent, counterparty, expiry, or acknowledgement commitments do not match.

## Transfer admission

A regulated transfer MAY finalize only when the selected `CompliancePolicyProfileV1` requires
and receives a valid P-120 envelope, a valid P-121 binding when applicable, an APL permit, and
all ordinary protocol authorization and conservation checks. Missing, stale, replayed, or
provider-unavailable evidence fails closed; permissionless transfers outside a regulated profile
are not retroactively represented as KYC-approved.

## Privacy and retention

KYC, sanctions, Travel Rule, monitoring, case, and reporting records are retained in authorized
encrypted systems subject to jurisdictional retention/deletion rules. Public commitments MUST be
non-enumerable and must not disclose that a person was screened, investigated, sanctioned, or
reported.
