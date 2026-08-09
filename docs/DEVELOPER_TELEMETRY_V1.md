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
- one evidence kind: `human_interaction`, `agent_execution`, `git_artifact`, `build_test`, or
  `model_usage`;
- source, subject, and private-payload commitments;
- bounded counters appropriate to the evidence kind;
- the collector authorization revision in force when accepted.

The collector rejects inverted ranges, zero commitments, duplicate sequences, unknown kinds,
events outside the authorization window, and counters inconsistent with their kind. Wall-clock
time never determines duration. Human attention requires trusted local interaction evidence and an
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
- idle timeout and maximum continuous human interval;
- agent-run overlap and concurrency treatment;
- token/model-unit normalization rules;
- build/test result treatment;
- project-attribution rules;
- rounding, minimum granularity, and excluded intervals;
- disclosure and non-overlap proof profile revisions.

Evidence and claims are separate. Re-evaluating an epoch under another policy produces another
claim ID and never rewrites evidence.

## Proof claims

Every claim binds collector, project, policy, epoch range/root, claim interval, evidence count,
claim kind, proof profile, and optional finalized anchor evidence.

- `AttentionProofV1` reports attributable human-attention milliseconds after idle and overlap
  policy. It never reports wall-clock session span as attention.
- `ComputeProofV1` reports agent runtime, model input/output tokens, normalized model units, and
  agent-run count. Concurrent runs remain distinct and are not converted to human time.
- `ContributionProofV1` binds human and agent evidence roots to an exact artifact commitment such
  as a Git commit, tree, release, test report, or build artifact.
- `NonOverlapProofV1` proves that disclosed billable human-attention intervals for the claim do not
  overlap intervals committed under the compared scope. Its public journal reveals claim IDs,
  policy ID, interval bounds, total billed duration, and a Boolean relation result, but not the
  other project/client identity or private intervals.

No claim is valid merely because its JSON parses. Verification requires canonical decoding,
collector signature verification, event/epoch Merkle inclusion, policy re-derivation, proof-profile
verification, and finalized anchor verification against caller-pinned chain and genesis when the
claim says `finalized`.

## Lifecycle

`observed -> accepted -> signed -> epoch_sealed -> anchor_pending -> anchor_finalized -> derived`

Terminal failures are `rejected`, `invalid`, or `deleted`. Missing, pending, stale, unsupported,
unavailable, and malformed states never map to verified. Deleting local evidence does not delete an
anchor; it makes later selective disclosure impossible and must be represented honestly.

## Privacy and retention

Collection categories default off. Authorization is per collector, project, category, purpose,
retention period, and revision. Pause is immediate and durable. Retention defaults to 30 days but
is operator-configurable. Export and deletion are local authenticated operations. Detailed
disclosure is never automatic and always identifies the requesting audience and purpose.

The machine-readable transport contract is
`testing/schemas/developer-telemetry-v1.schema.json`; examples are frozen in
`testing/vectors/developer-telemetry-v1.json`.
