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

`work.prove` uses the ActiveChain-owned `actum-work-prover` sidecar over a private mode-0600 Unix
socket in a mode-0700 directory. Its input schema is
`schemas/actum-work-prover-source-v1.schema.json`: a Rust collector-produced sealed epoch plus the
complete signed event set and requested claim class. The sidecar independently verifies every
ML-DSA event signature and epoch binding, builds the canonical class witnesses/aggregate and
class-neutral usage nullifiers, keeps the claimant secret in a private operator file, invokes the
pinned RISC Zero prover, and emits an `actum.work-proof.admit.request.v1` artifact. ProofOfWork and
the Python plugin never construct canonical event IDs, Merkle paths, claims, proofs, or anchor
requests. The plugin will extract anchor bytes only from a successful sidecar artifact recorded in
its durable request journal.

The sidecar config is frozen by `schemas/actum-work-prover-config-v1.schema.json` with schema
identifier `actum.work-prover.config.v1` and contains exact lowercase
chain, genesis, usage-domain, and submitter digests; a canonical policy envelope; an absolute
private claimant-secret file; and a private output directory under plugin data. Both config and
secret files must be regular, non-symlink, mode-0400/0600 files. The config also pins the absolute
`r0vm` executable; the daemon always proves through that isolated subprocess. Set the client
executable with `ACTUM_WORK_PROVER`, the socket path with `ACTUM_WORK_PROVER_SOCKET`, and an optional bounded
`ACTUM_WORK_PROVER_TIMEOUT_SECONDS=30..900`. Start the key-owning process separately with
`actum-work-prover --serve /absolute/private/config.json`; the plugin client never reads that
config or the claimant secret.

Example private daemon config (all placeholders are exact lowercase canonical values, not browser
configuration):

```json
{
  "schema": "actum.work-prover.config.v1",
  "chain_id": "<96 lowercase hex>",
  "genesis_commitment": "<96 lowercase hex>",
  "usage_domain": "<96 lowercase hex>",
  "submitter_id": "<96 lowercase hex>",
  "policy_envelope_hex": "<canonical MeteringPolicyV1 envelope hex>",
  "claimant_secret_file": "/private/actum/claimant-secret.hex",
  "output_directory": "/private/plugin-data/work-proofs",
  "socket_path": "/private/actum/work-prover.sock",
  "r0vm_path": "/absolute/path/to/r0vm"
}
```

The source artifact is schema-validated JSON transport, but all identifiers, signatures, epoch
bindings, witnesses, claims, anchor requests, and proofs are re-derived or canonically decoded by
Rust before use. The daemon atomically publishes a private request directory, returns the same
artifact for an exact request/source retry, and rejects the same request ID with different source
bytes.

`ACTUM_DELIVERY_WEBHOOK` and `ACTUM_ANCHOR_URL` are optional Preview integrations. Delivery requires
a private regular `ACTUM_DELIVERY_BEARER_TOKEN_FILE`, just as anchoring requires its protected token
file; neither credential is accepted through an MCP argument or returned. Delivery does not imply
anchoring, finalized anchoring does not imply relation verification, and verification does not
imply usage-nullifier admission.

## Verification service contract

#777 ships the safe Rust verification service, authenticated bounded HTTP adapter, and bounded
relation-verifier subprocess. Run `actum-work-proof-api` behind TLS with a private bearer-token file;
the adapter is not a trust boundary and delegates all verification and usage admission to
`activechain-work-proof-verifier`.

```text
GET  /v1/status
POST /v1/proofs/verify
GET  /v1/claims?cursor=<claim_id>&limit=<1..100>
GET  /v1/claims/{claim_id}
```

`POST /v1/proofs/verify` accepts canonical `WorkProofReceiptEnvelopeV1` bytes, the canonical epoch
anchor request, revision-2 `CheckpointedTelemetryAnchorEvidenceV1`, and a caller identity used only
for bounded rate limiting. The checkpoint evidence contains the exact finalized native anchor record
and bounded canonical state proof. Binary fields use lowercase hex in JSON adapters. The service loads its accepted trust
bundle from durable operator state; neither the proof nor the request can select or install trust.
The service derives and checks `claim_id` from the canonical public claim and proof commitment.

A successful `VerifiedClaimDtoV1` has all three independent facts set:

- `relation_verified`: the operator-pinned RISC Zero image accepted the canonical relation journal;
- `anchor_verified`: the request-derived epoch statement is bound to a native anchor action and
  receipt under valid Actum finality at block A, and the exact consensus-created anchor record has a
  valid state-membership proof under accepted checkpoint C with A.height <= C.height;
- `usage_verified`: every class-neutral usage nullifier was atomically admitted in its usage domain.

The service registers nullifiers only after relation and anchor verification. Registration is one
all-or-nothing durable operation. An exact retry of the same derived claim is idempotent; any
nullifier already bound to a different claim rejects the entire request without inserting new
nullifiers. Multiple admission processes may share one registry file: each process takes the same
owner-only OS lock, reloads durable state after acquiring it, and holds the lock through collision
checks, temporary-file fsync, atomic rename, and parent-directory fsync. Stateless relation workers
may scale independently. A single admission process remains operationally preferable while the
complete-file registry is Preview because concurrent writers serialize and every accepted claim
rewrites the complete file.

### Preview durable-registry bounds

The v1 `BTreeMap` registry is deliberately bounded Preview storage, not the production scaling
design. `MAX_USAGE_ENTRIES` is 1,000,000 and `MAX_USAGE_FILE_BYTES` is 164,000,012 bytes. Admission
fails closed before exceeding either bound. The logical all-or-nothing and exact-claim-idempotency
semantics are storage-independent; a later SQLite, LMDB, or transactional KV implementation must
preserve them exactly.

The ignored operational profile can be reproduced with:

```sh
RISC0_SKIP_BUILD=1 cargo test --locked -p activechain-work-proof-verifier \
  multiprocess_tests::usage_registry_operational_load_profile -- \
  --ignored --exact --nocapture --test-threads=1
```

On 2026-08-10, an Apple ARM64 laptop running the unoptimized test profile measured one admission
after loading a registry at each scale:

| Entries after admission | Registry bytes | Open | Admission |
| ---: | ---: | ---: | ---: |
| 10,000 | 1,640,012 | 16 ms | 36 ms |
| 100,000 | 16,400,012 | 152 ms | 221 ms |
| 500,000 | 82,000,012 | 704 ms | 1,207 ms |
| 1,000,000 | 164,000,012 | 1,557 ms | 2,340 ms |

These are qualification observations from one machine, not latency guarantees. In particular,
the 500k and 1m results are operational evidence that complete-file persistence must remain
**Preview** and should be replaced before production-scale admission.

Errors use bounded `VerificationErrorCodeV1` values for malformed, oversized, unsupported,
relation-invalid, anchor-pending, anchor-rejected, anchor-invalid, wrong-network, trust-invalid, double-use,
rate-limited, unavailable, and internal failures. Error detail is bounded and must not contain
receipt bytes, telemetry, credentials, subprocess stderr, or filesystem paths. HTTP 2xx means only
that the request was processed. Only a response with all three facts true may render a verified
check mark.

The operator persists the highest accepted chained `SignedActumVerifierTrustBundleV1`. Bootstrap
and rotation validate signatures, sequence, previous bundle ID, signer-set transition, validity
window, network/genesis, checkpoint, image, verifier, proof profile, and policy. A proof submission
cannot replace this state. Explorer pagination returns only bounded claim summaries; detailed DTOs
contain public aggregates and finalized-anchor identifiers, never raw telemetry or private evidence.

Provision bootstrap trust with canonical signed-bundle and signer-set envelopes:

```sh
actum-work-proof-trust-bootstrap \
  /private/verifier/trust.bin \
  /private/operator/signed-trust-bundle.bin \
  /private/operator/trust-signer-set.bin \
  "$NOW_MS"

actum-work-proof-api \
  127.0.0.1:49157 \
  /private/verifier/trust.bin \
  /private/verifier/usage.bin \
  /opt/actum/bin/actum-work-proof-verifier \
  /private/verifier/bearer.token
```

The bootstrap tool verifies threshold ML-DSA signatures before writing private durable trust state.
Bootstrap refuses to replace an existing trust store; signer rotation must use the verified chained
transition API so sequence rollback and forked predecessors remain impossible.
The API never accepts a trust bundle from a request. The bearer is transport authorization only and
must remain outside browser code, telemetry, logs, evidence, and command-line arguments.

The stateful request schema is `actum.work-proof.admit.request.v1` with operation
`verify_and_register`, profile `actum.non-overlap.risc0.v1`, and lowercase-hex fields
`claim_id`, `public_claim_envelope_hex`, `proof_envelope_hex`,
`anchor_request_envelope_hex`, and `checkpointed_anchor_evidence_envelope_hex`. Unknown fields, oversized bodies,
noncanonical hex/envelopes, unsupported profiles, and caller-supplied trust fail closed.

`CheckpointLag` is retryable: the anchor is natively valid but newer than the operator-selected
checkpoint. `CheckpointUnavailable` is retryable when the client cannot yet supply checkpoint
evidence; the JSON field may be omitted or `null` in that state. `InvalidAnchor` is terminal for
malformed native finality, wrong network or statement, checkpoint substitution, or a supplied state
proof that does not authenticate the exact derived record.

### ProofOfWork migration

The earlier ProofOfWork `ACTUM_FINALITY_VERIFIER` adapter sends a request-supplied `trust_bundle` to
an anchor-only subprocess. Keep that compatibility path **Preview** and do not map its success to
production `anchor_verified`: submitted evidence is not allowed to choose verifier trust. For the
qualified path, configure the Agent Plugin with `ACTUM_WORK_VERIFIER_URL` and a private
`ACTUM_WORK_VERIFIER_BEARER_TOKEN_FILE`, then submit the complete canonical stateful request to this
service. The service operator installs trust with `actum-work-proof-trust-bootstrap`; the
ProofOfWork `EvidenceBundleV1`, browser, plugin arguments, and HTTP body must not carry or replace
that durable trust state. Use `/v1/status` readiness and the three returned verification dimensions
instead of inferring readiness or finality from HTTP success.

Reference integration artifacts:

- `schemas/actum-work-proof-admission-v1.schema.json` freezes the HTTP request, success, and typed
  error envelopes.
- `testing/contracts/proof-of-work-verifier-v1.json` supplies stateless and stateful consumer
  fixtures without caller-selected trust.
- `docs/examples/pow-work-proof-client.ts` is a server-side TypeScript client that enforces HTTPS,
  bounded responses, exact fields, canonical lowercase encodings, and chain/project/policy/result
  bindings. Bearer material must never be shipped to browser code.

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
