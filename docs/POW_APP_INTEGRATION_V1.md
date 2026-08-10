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
| ZK non-double-billing | class-neutral usage-nullifier profile | #776/#777 | Stateless relation and durable atomic admission implemented; qualification pending |
| Proof explorer and verification API | API below | #777 | Implemented candidate; qualification pending |
| Verified invoice/work statement | verified claim composition | #777/#778 | Verification candidate implemented; end-to-end qualification pending |
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

## Verification service contract

#777 ships the safe Rust verification service and bounded verifier subprocess. A production HTTP
adapter may expose the following routes with media type
`application/vnd.actum.work-proof.v1+json`; that adapter is not a trust boundary and must delegate
all verification and usage admission to `activechain-work-proof-verifier`.

```text
GET  /v1/status
POST /v1/proofs/verify
GET  /v1/claims/{claim_id}
GET  /v1/epochs/{epoch_id}
POST /v1/disclosures/verify
```

`POST /v1/proofs/verify` accepts canonical `WorkProofReceiptEnvelopeV1` bytes, exact finalized
anchor evidence, the operator-selected trust bundle, and a caller identity used only for bounded
rate limiting. Binary fields use lowercase hex in JSON adapters. The proof may name an expected
bundle but cannot select or install trust. The service derives `claim_id` from the canonical public
claim and proof commitment; callers cannot supply it.

A successful `VerifiedClaimDtoV1` has all three independent facts set:

- `relation_verified`: the operator-pinned RISC Zero image accepted the canonical relation journal;
- `anchor_verified`: the exact epoch anchor is included in finalized Actum state connected to the
  accepted checkpoint bundle;
- `usage_verified`: every class-neutral usage nullifier was atomically admitted in its usage domain.

The service registers nullifiers only after relation and anchor verification. Registration is one
all-or-nothing durable operation. An exact retry of the same derived claim is idempotent; any
nullifier already bound to a different claim rejects the entire request without inserting new
nullifiers. Run one stateful admission service for each registry file; stateless relation workers
may scale independently.

Errors use bounded `VerificationErrorCodeV1` values for malformed, oversized, unsupported,
relation-invalid, anchor-pending, anchor-rejected, anchor-invalid, trust-invalid, double-use,
rate-limited, unavailable, and internal failures. Error detail is bounded and must not contain
receipt bytes, telemetry, credentials, subprocess stderr, or filesystem paths. HTTP 2xx means only
that the request was processed. Only a response with all three facts true may render a verified
check mark.

The operator persists the highest accepted chained `SignedActumVerifierTrustBundleV1`. Bootstrap
and rotation validate signatures, sequence, previous bundle ID, signer-set transition, validity
window, network/genesis, checkpoint, image, verifier, proof profile, and policy. A proof submission
cannot replace this state. Explorer pagination returns only bounded claim summaries; detailed DTOs
contain public aggregates and finalized-anchor identifiers, never raw telemetry or private evidence.

## Offline and subprocess interfaces

The `actum-work-proof-verifier` executable accepts one length-prefixed binary request on stdin and
returns one bounded binary response on stdout. The parent enforces input/output limits and a hard
timeout, kills a stalled child, rejects trailing bytes, and never exposes child stderr. The child is
stateless and verifies only the relation; finality, trust-state mutation, and usage admission remain
in the parent service.

Rust callers use `activechain-work-proof-verifier`. C, Swift, and other FFI clients can call
`activechain_verify_work_relation_code` from `activechain_verifier.h` for bounded offline relation
verification. A zero return value means relation success; nonzero values are fail-closed verifier
codes. Offline relation success never implies anchor or usage verification.

ProofOfWork and other JSON subprocess consumers use `actum-work-proof-json-verifier`. Send exactly
one `actum.work-proof.verify.request.v1` object on stdin with operation `verify_non_overlap`, profile
`actum.non-overlap.risc0.v1`, `proof.proof_envelope_hex`, and
`expected.public_claim_envelope_hex`. The adapter rejects unknown fields and non-lowercase hex and
returns exactly one `actum.work-proof.verify.result.v1` object with `VERIFIED`, `INVALID`,
`UNSUPPORTED`, or `MALFORMED`. Only `VERIFIED` has `verified: true`.

Cache only by the complete receipt-envelope commitment plus accepted trust-bundle ID. Never infer
chain, genesis, image, policy, or checkpoint from an untrusted submission.

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
  consumed twice in one usage domain after durable #777 admission.
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

Canonical telemetry, epoch, work-proof journal, image, receipt, and negative vectors live under
`testing/vectors`. JSON schema fixtures are presentation examples and do not replace canonical
binary vectors or the verifier's pinned RISC Zero image ID.

## Integration checklist

1. Pin schema, API, proof-profile, chain, genesis, protocol, and verifier revisions.
2. Obtain collector permission state locally; never infer it from plugin installation.
3. Treat summaries as unverified until proof verification returns `verified`.
4. Resolve finalized anchor evidence and verify it independently.
5. Keep raw evidence local unless the user approves a bounded audience/purpose disclosure.
6. Test malformed JSON, oversized fields, substitutions, replay, wrong network, stale finality,
   unknown profiles, missing evidence, deleted evidence, and API unavailability.
7. Keep every unimplemented control labelled Preview and non-interactive.
