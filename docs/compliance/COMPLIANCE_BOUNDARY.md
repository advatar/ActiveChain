# Compliance boundary and control taxonomy

Status: normative boundary for design; not a statement that controls are implemented.

ActiveChain MUST distinguish protocol guarantees from accountable off-chain decisions. Each
control is classified as one of the following:

| Class | Meaning | Examples | Evidence required |
|---|---|---|---|
| Consensus-enforced | Deterministic state, authorization, proof, replay, and conservation rules | Canonical envelopes, AssetId binding, finality, supply conservation | Reproducible tests, vectors, formal scope, auditor re-performance |
| Application-enforced | Wallet/operator checks before submission | Credential freshness, screening result required, Travel Rule acknowledgement | Versioned profile, negative tests, signed control receipt |
| Provider-operated | External service execution and data quality | KYC issuer, sanctions lists, analytics, payment/custody provider | Contract, provider version/SLA, independent confirmation, reconciliation |
| Manually operated | Human judgement and escalation | Case investigation, overrides, SAR/STR decision, freeze release | Segregation of duties, case record, approval, sampling |
| Outside scope | Not claimed or not observable by the protocol | Legal classification, document authenticity, whether conduct is suspicious | Explicit limitation and counsel/owner responsibility |

For every regulated profile, maintain a control register with `control_id`, revision, risk,
class, owner, input, decision, authority, failure/timeout behavior, override authority,
evidence ID, retention, privacy class, and Applicable/Not applicable/Not examined status.

The base protocol MUST NOT infer identity, KYC completion, sanctions clearance, suspiciousness,
licensing, reserve sufficiency, or regulator approval from a chain principal, credential,
policy permit, or receipt alone.
