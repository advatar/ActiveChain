# P-131 — ActiveChain protocol version series

Status: normative launch sequencing decision.

Every version dispatches from the explicit protocol-version field. A v1 client MUST reject
unknown type tags, header extensions, and transition actions; it MUST NOT ignore or reinterpret
them. Genesis reserves the extension ranges below so later versions add semantics without
changing the meaning of v1 bytes.

Canonical v1 type assignments use `0x0020..0x00d9` and the sparse extension block
`0x0100..0x01ff`. The `0x00e0..0x00ef` block remains reserved for v1.1 activation and
`0x00f0..0x00ff` remains reserved for v1.2 activation. Registration in the v1 extension block does
not activate a deferred feature; it only gives already implemented v1 development types globally
unique identities.

| Version | Mandatory surface | Reserved/deferred surface |
|---|---|---|
| v1.0 | PQ authorization and consensus signatures, principals/recovery, attenuated capabilities, APL, ObjectVM, multidimensional fees/state rent, public cash lane, light-client verification, validator re-execution | validity-proof header slot, private-object tags, protected-ordering tag, compute-job tags |
| v1.1 | Consensus-required execution validity proofs after parameter and liveness qualification | private credentials and shielded payment tags |
| v1.2 | Private credential presentation, shielded payments, private objects and viewing capabilities | protected-ordering requirement |
| v1.3 | Protected transaction lane as a mandatory admission path | compute-job objects and assurance tiers |
| v1.4 | Compute-job objects and bounded assurance tiers, only after their admission proof is complete | stateless validators and external bridges |
| v2 | Stateless active validators and external bridges, each with independent migration and safety gates | none implied |

## Release gates

No version becomes consensus-required merely because its encoding is reserved. Each activation
requires deterministic positive/negative vectors, an independent implementation or model for the
activated surface, migration/replay analysis, and an explicit liveness assessment. Until v1.1
proofs are qualified, v1.0 validator re-execution remains authoritative and proof receipts are
advisory evidence.

## Unknown-tag rule

Reserved ranges are not wildcards. A client that encounters a reserved or future tag returns a
version/feature error and leaves state unchanged. This rule is part of the v1 conformance suite.
