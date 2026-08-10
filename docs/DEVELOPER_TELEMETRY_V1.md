# Actum developer telemetry contract v1

Status: **frozen developmental contract; collection, proof generation, and verification services are
not shipped yet**. This document is normative for issues #773 through #778.

## Boundary

Developer telemetry is an application protocol outside consensus. Consensus sees only a finalized
digest-anchor statement. Raw events, project names, repository paths, prompts, source, diffs,
client names, credentials, model transcripts, and local policy remain off-chain.

The coding agent is an untrusted observation source. The local collector owns authorization,
project attribution, durable sequence allocation, signing, retention, deletion, epoch construction,
and disclosure. Installing the plugin grants none of those authorities.

## Identifiers and commitments

All hexadecimal identifiers are lowercase and fixed width:

| Value | Derivation |
| --- | --- |
| `collector_id` | SHA3-384 commitment to the collector's versioned ML-DSA public-key record |
| `project_id` | keyed local SHA3-384 commitment to canonical repository identity; never a path |
| `event_id` | SHA3-384 canonical-value commitment to the unsigned event plus collector ID |
| `epoch_id` | SHA3-384 canonical-value commitment to the activity epoch |
| `policy_id` | SHA3-384 canonical-value commitment to the complete metering policy |
| `claim_id` | SHA3-384 canonical-value commitment to the complete proof claim |
| `artifact_commitment` | SHA3-384 domain-separated commitment to artifact kind and digest |

JSON is transport data and is not hashed directly. Implementations must use the canonical binary
encodings and vectors delivered with the implementing issues before claiming interoperability.

## Event model

A `DeveloperEventV1` contains:

- exact collector and project IDs;
- a gap-free collector sequence and a project-local sequence;
- wall-clock UTC bounds for display and monotonic bounds for duration;
- one tagged raw measurement: `human_interaction { interaction_count }`,
  `agent_execution { run_count }`, `git_artifact { artifact_count }`,
  `build_test { run_count, test_count }`, or
  `model_usage { input_tokens, output_tokens, run_count }`;
- source, subject, and private-payload commitments;
- bounded counters structurally limited to the selected measurement kind;
- the collector authorization revision in force when accepted.

The collector rejects inverted ranges, zero commitments, duplicate sequences, unknown kinds,
events outside the authorization window, and invalid atomic counters. Human, agent, artifact, and
model run counts are exactly one in v1; build/test `test_count` may exceed one, and model usage
requires at least one nonzero token count. Wall-clock time never determines duration. Human
attention requires trusted local interaction evidence and an
idle policy; an agent message claiming that a human was present is insufficient.

`SignedDeveloperEventV1` binds the canonical event, ML-DSA algorithm revision, collector public-key
record, and signature. The signature domain is `actum.developer-event.v1`.

## Activity epochs

An `ActivityEpochV1` commits to one collector/project pair, an exact contiguous sequence range,
event count, time range, Merkle event root, prior epoch ID (or genesis zero), authorization revision,
and policy ID. Leaves are `H(0x00 || event_id)` and internal nodes are
`H(0x01 || left || right)` using SHA3-384. Odd final nodes duplicate the rightmost child. Empty
epochs are invalid.

The anchor statement uses application domain `actum.developer-telemetry.epoch.v1` and the SHA-256
digest of the canonical epoch envelope. Batching may use the existing `AnchorBatchProofV1`.

## Metering policy

`MeteringPolicyV1` is immutable and versioned. It declares:

- accepted evidence kinds and required source assurance;
- `idle_timeout_ms`, `max_human_event_ms`, and `max_attention_claim_ms`;
- model input/output integer weights with fixed denominator `1_000_000`;
- build/test result treatment;
- project-attribution rules;
- accepted measurement kinds;
- disclosure and non-overlap proof profile revisions.

## Canonical telemetry-construction authority

Applications submit raw observations to an Actum-owned telemetry-construction authority.
Applications MUST NOT construct `DeveloperEventV1` IDs, canonical sequence numbers, canonical
monotonic durations, or epoch Merkle roots. The authority validates permission and project scope,
allocates durable sequences, derives monotonic intervals, constructs canonical events, signs them,
and seals linked epochs.

The initial reference authority is an Actum Rust sidecar reached over a local Unix-domain socket.
The socket is not consensus or protocol semantics. In-process FFI, named pipes, and mobile platform
services may implement the same trusted construction boundary later, provided applications still
submit raw observations and cannot choose canonical identities or ordering.

Evidence and claims are separate. Re-evaluating an epoch under another policy produces another
claim ID and never rewrites evidence.

## Proof claims

Every claim binds collector, project, policy, epoch range/root, claim interval, evidence count,
a tagged class-specific aggregate, proof profile, and optional finalized anchor evidence.

- `AttentionProofV1` reports attributable milliseconds and interaction count. Each duration is
  `floor((monotonic_end_ns - monotonic_start_ns) / 1_000_000)`, clipped by the policy idle/event
  limits, then canonical intervals are unioned and capped by `max_attention_claim_ms`.
- `ComputeProofV1` reports summed agent/build runtime, raw model input/output tokens, normalized
  model units, and run count. Concurrent runs sum independently. Tokens aggregate before one
  checked `floor((input * input_weight + output * output_weight) / 1_000_000)` operation.
- `ContributionProofV1` publishes distinct artifact count, a domain-separated commitment to
  lexicographically sorted artifact identities, and a deterministic evidence root. It is not a
  synthetic time or token score.
- `WorkProofReceiptEnvelopeV1` carries the canonical class-specific public claim, the pinned RISC
  Zero image identity, and the succinct receipt. The relation permits overlapping Compute events,
  unions overlapping Attention intervals, and treats Contribution as attributed artifact evidence.
  Class-neutral usage nullifiers are public; class-specific nullifiers remain committed. #777
  atomically enforces usage uniqueness after independent relation and finalized-anchor verification.

No claim is valid merely because its JSON parses. Verification requires canonical decoding,
collector signature verification, event/epoch Merkle inclusion, policy re-derivation, proof-profile
verification, and finalized anchor verification against caller-pinned chain and genesis when the
claim says `finalized`.

## Lifecycle

`observed -> accepted -> signed -> epoch_sealed -> anchor_pending -> anchor_finalized -> derived`

Terminal failures are `rejected`, `invalid`, or `deleted`. Missing, pending, stale, unsupported,
unavailable, and malformed states never map to verified. Deleting local evidence does not delete an
anchor; it makes later selective disclosure impossible and must be represented honestly.

## Production anchor service

`ACTUM_ANCHOR_URL` targets the TLS-terminated `POST /v1/anchors` endpoint served behind
`activechain-telemetry-anchor-gateway`. The request body is the canonical
`TelemetryEpochAnchorRequestV1` envelope, `Content-Type` is `application/octet-stream`,
`X-Actum-Request-Id` exactly matches the canonical request ID, and `Authorization` is a bearer
credential read by the gateway from a mode-0600 `ACTUM_ANCHOR_BEARER_TOKEN_FILE`. The gateway is
plain HTTP by design and must bind privately behind an HTTPS reverse proxy; public cleartext use is
unsupported.

The gateway also requires `ACTUM_ANCHOR_IDEMPOTENCY_JOURNAL`. It durably reserves the canonical
request commitment under `X-Actum-Request-Id` before contacting RPC. Exact retries remain safe
across restart; the same ID with different canonical bytes fails with `idempotency_conflict` and
cannot submit another statement. The journal is bounded to 65,536 records and fails closed when
full, corrupt, unavailable, symlinked, or group/world accessible.

Responses are bounded JSON with `status` equal to `submitted`, `pending`, `finalized`, or
`rejected`, plus the pinned 96-character lowercase `chain_id`, `genesis_commitment`, and anchor
`reference`. Retries with the same canonical request are idempotent. Reusing a request ID with
different canonical bytes is rejected by the request/statement binding. Wrong-network requests,
malformed backend records, stale health, timeouts, and unavailable RPC fail closed and never become
`finalized`. Authenticated `GET /v1/health` reports `healthy` only when the canonical RPC backend
reports healthy finalized state and the native anchor registry, funded operator fee account, nonce
channel, and single-action proposal spool are ready to accept a new submission.

Finalization remains an operator action through `activechain-anchor-admin`; the gateway cannot
manufacture finality. A `finalized` response means the exact statement has a finalized registry
record. Verification requires both independently verified `AnchorFinalizedEvidenceV1` and the
revision-2 `CheckpointedTelemetryAnchorEvidenceV1` fixed-depth `StateProof`. The native action,
anchor receipt, and finality certificate bind the request-derived statement to exact anchor block A;
the state proof authenticates the consensus-created immutable anchor object under operator-selected
checkpoint C. These facts are checked independently with A.height <= C.height. An anchor newer than
the current checkpoint is pending/retryable. A gateway response or host registry record alone is never
`anchor_verified`.

## Privacy and retention

Collection categories default off. Authorization is per collector, project, category, purpose,
retention period, and revision. Pause is immediate and durable. Retention defaults to 30 days but
is operator-configurable. Export and deletion are local authenticated operations. Detailed
disclosure is never automatic and always identifies the requesting audience and purpose.

The machine-readable transport contract is
`testing/schemas/developer-telemetry-v1.schema.json`; examples are frozen in
`testing/vectors/developer-telemetry-v1.json`.
