# `pow.actum.network` developer integration v1

Audience: developers of the `pow.actum.network` web application and verification service.

## Current implementation status

The deployed page is currently a presentation prototype. It makes no Actum proof/collector API
calls and displays illustrative values. Keep all install, pause, proof, explorer, invoice,
verification, and settlement controls disabled or labelled **Preview** until their row is shipped.

| Capability shown by the app | Contract | Implementation issue | Current status |
| --- | --- | --- | --- |
| Agent Plugin packaging | Agent Plugins 1.0 + Codex extension | #774 | Planned; node-operations plugin #767 is not telemetry |
| Human/agent/Git/build/model collection | `DeveloperEventV1` | #773 | Planned |
| Permission UI, pause, retention, deletion | collector authorization API | #773 | Planned |
| Project attribution and activity graph | keyed project identity | #773 | Planned |
| Signed events and activity epochs | `SignedDeveloperEventV1`, `ActivityEpochV1` | #773 | Planned |
| Actum commitments/finality | digest-anchor profile | #775 | Reusable anchor exists; telemetry integration planned |
| Attention/Compute/Contribution proofs | work-proof profiles | #776 | Planned |
| ZK non-double-billing | non-overlap RISC Zero profile | #776 | Planned |
| Proof explorer and verification API | API below | #777 | Planned |
| Verified invoice/work statement | verified claim composition | #777/#778 | Planned |
| Payments or autonomous settlement | separate wallet-approved action | later policy | Not authorized by telemetry |

## Plugin layout

The shipped package name is `actum-developer-telemetry`:

```text
actum-developer-telemetry/
├── plugin.json
├── mcp.json
├── .codex-plugin/plugin.json
├── .mcp.json
└── skills/
    ├── telemetry/SKILL.md
    ├── project-attribution/SKILL.md
    ├── prove-work/SKILL.md
    └── verify-work/SKILL.md
```

Installation does not authorize collection. The host displays requested capabilities; the local
collector records explicit grants.

## Local MCP contract

Names are reserved for #774. Consequential tools require explicit user approval and collector
authentication; read tools never expose raw evidence by default.

| Tool/resource | Class | Result |
| --- | --- | --- |
| `actum_telemetry_get_status` | read | enabled categories, pause state, collector/project IDs, retention, pending epochs |
| `actum_telemetry_configure` | consequential | proposed category/project/purpose/retention grant |
| `actum_telemetry_pause` / `resume` | consequential | durable state transition |
| `actum_telemetry_query_summary` | read | derived local totals and assurance labels |
| `actum_telemetry_seal_epoch` | consequential | signed epoch; never remote submission |
| `actum_telemetry_propose_anchor` | consequential proposal | native approval-bound digest-anchor proposal |
| `actum_telemetry_derive_proof` | consequential local | proof under exact policy/profile |
| `actum_telemetry_verify_proof` | read | fail-closed verification result |
| `actum_telemetry_export` / `delete` | consequential local | authenticated bounded export/deletion operation |

## Verification HTTP API

The API is not live until #777. Version with media type
`application/vnd.actum.work-proof.v1+json`. Requests and responses conform to
`testing/schemas/developer-telemetry-v1.schema.json`.

```text
GET  /v1/status
POST /v1/proofs/verify
GET  /v1/claims/{claim_id}
GET  /v1/epochs/{epoch_id}
POST /v1/disclosures/verify
```

`POST /v1/proofs/verify` accepts a `WorkProofEnvelopeV1` and caller-pinned trust parameters. It
returns `VerificationResultV1` with one status:

- `verified`: every required local proof and, when declared, finalized anchor passed;
- `pending`: exact anchor is accepted but not finalized;
- `rejected`: terminal authoritative rejection;
- `invalid`: malformed, substituted, unverifiable, wrong-network, stale, or failed proof;
- `unsupported`: unknown profile/revision;
- `unavailable`: required verifier/network evidence could not be obtained.

Only `verified` may render a check mark. HTTP 2xx means the request was processed, not that the
claim verified. Cache verification only by the complete envelope commitment plus trust-policy
revision. Never infer chain/genesis from the submitted proof.

## Frontend state rules

- Display measured human attention, agent runtime, and wall-clock workflow span separately.
- Label token/model counters as measured or estimated and show accounting revision.
- Display project aliases only from local/user disclosure; never reverse project commitments.
- Show policy/profile revisions and collector assurance with every proof.
- Show `pending`, `invalid`, `unsupported`, and `unavailable` distinctly.
- A finalized anchor proves timestamped commitment/finality, not truth of raw observations.
- A ContributionProof links evidence to an artifact; it does not prove code quality or sole authorship.
- A non-overlap proof covers only its declared scope and policy.
- Do not send raw telemetry to Lovable/Tinybird or generic analytics.

## Example

`testing/vectors/developer-telemetry-v1.json` contains one event, epoch, policy, three claim types,
a non-overlap public journal, proof envelope, and fail-closed verification outcomes. These values
are schema fixtures, not yet canonical cryptographic vectors. #773 and #776 will replace placeholder
proof bytes with generated canonical/signature/image vectors while preserving the JSON shape.

## Integration checklist

1. Pin schema, API, proof-profile, chain, genesis, protocol, and verifier revisions.
2. Obtain collector permission state locally; never infer it from plugin installation.
3. Treat summaries as unverified until proof verification returns `verified`.
4. Resolve finalized anchor evidence and verify it independently.
5. Keep raw evidence local unless the user approves a bounded audience/purpose disclosure.
6. Test malformed JSON, oversized fields, substitutions, replay, wrong network, stale finality,
   unknown profiles, missing evidence, deleted evidence, and API unavailability.
7. Keep every unimplemented control labelled Preview and non-interactive.
