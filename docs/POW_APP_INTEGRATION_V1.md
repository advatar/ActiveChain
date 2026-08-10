# `pow.actum.network` developer integration v1

Audience: developers of the `pow.actum.network` web application and verification service.

## Current implementation status

The deployed page is currently a presentation prototype. It makes no Actum proof/collector API
calls and displays illustrative values. Keep all install, pause, proof, explorer, invoice,
verification, and settlement controls disabled or labelled **Preview** until their row is shipped.

| Capability shown by the app | Contract | Implementation issue | Current status |
| --- | --- | --- | --- |
| Agent Plugin packaging | Agent Plugins 1.0 + Codex extension | #774 | Candidate implemented; remains Preview pending exact qualification |
| Human/agent/Git/build/model collection | `DeveloperEventV1` | #773/#776 | Collector merged; tagged raw-measurement correction remains Preview pending #776 qualification |
| Permission UI, pause, retention, deletion | collector authorization API | #773/#774 | Collector and plugin candidates implemented; remains Preview until merged |
| Project attribution and activity graph | keyed project identity | #773 | Planned |
| Signed events and activity epochs | `SignedDeveloperEventV1`, `ActivityEpochV1` | #773/#776 | Collector merged; corrected event/epoch vectors pending #776 qualification |
| Actum commitments/finality | digest-anchor profile | #775 | Qualified and merged; remains Preview until end-to-end promotion |
| Attention/Compute/Contribution proofs | tagged `WorkClaimAggregateV1` | #776 | Implemented candidate; vectors/image qualification pending |
| ZK non-double-billing | non-overlap RISC Zero profile | #776/#777 | Stateless relation implemented; durable atomic usage admission remains #777 |
| Proof explorer and verification API | API below | #777 | Planned |
| Verified invoice/work statement | verified claim composition | #777/#778 | Planned |
| Payments or autonomous settlement | separate wallet-approved action | later policy | Not authorized by telemetry |

## Plugin layout

The shipped portable package is `plugins/actum-telemetry`:

```text
actum-telemetry/
├── plugin.json
├── mcp.json
├── .codex-plugin/plugin.json
├── .mcp.json
├── bin/actum-telemetry-mcp
└── skills/actum-telemetry/SKILL.md
```

Installation does not authorize collection. The host supplies a private `PLUGIN_DATA` directory;
the operator separately supplies `ACTUM_TELEMETRY_CAPABILITY` for mutating calls. MCP stores only
bounded authorization/control metadata and idempotency receipts. Collector signing keys remain
outside the plugin process.

## Local MCP contract

Every mutating tool requires an explicit capability, request ID, and exact project scope. Unknown
fields and oversized values fail closed. Results never contain the capability, environment values,
auth headers, raw evidence, source, prompts, or command output.

| Tool | Class | Result |
| --- | --- | --- |
| `telemetry.status` | read | authorization, pause state, journal health, integration presence, pinned network identity |
| `telemetry.authorize` | consequential | explicit categories, purpose, project/policy IDs, revision, and retention window; remains paused |
| `telemetry.pause` / `telemetry.resume` | consequential | durable idempotent collection control |
| `telemetry.export` / `telemetry.delete` | consequential | project-scoped local control export/deletion; anchors are never deleted |
| `work.prove` | consequential | bounded subprocess result from an operator-pinned prover |
| `work.deliver` | consequential | delivery-only lifecycle from `ACTUM_DELIVERY_WEBHOOK` |
| `work.anchor` | consequential | submitted/pending/finalized/rejected anchor lifecycle from `ACTUM_ANCHOR_URL` |
| `work.verify` | consequential | separate `relation_verified`, `anchor_verified`, and `usage_verified` results from an operator-pinned verifier |

`ACTUM_DELIVERY_WEBHOOK` and `ACTUM_ANCHOR_URL` are optional Preview integrations. Their values are
never returned. Delivery does not imply anchoring, finalized anchoring does not imply relation
verification, and verification does not imply usage-nullifier admission.

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

## Canonical proof arithmetic

Telemetry stores raw tagged measurements. The proof recomputes economic/scoring quantities under
the exact committed `MeteringPolicyV1`; clients must never reinterpret event counters directly.

- Attention accepts only human-interaction events, floors monotonic nanoseconds to milliseconds,
  clips each interval by idle/event limits, unions overlaps and adjacency, then applies the claim cap.
- Compute accepts agent execution, build/test, and model usage. Agent/build runtime sums even when
  intervals overlap. Token totals aggregate before one checked millionth-weight normalization.
- Contribution accepts distinct contribution-qualified Git artifacts and publishes only artifact
  count, artifact-set commitment, and evidence root.
- A public usage nullifier is class-neutral. Different events may overlap; the same event cannot be
  consumed twice in one usage domain after #777 admission.
- Every conversion rounds down and uses checked integer arithmetic. Floating point is forbidden.

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
