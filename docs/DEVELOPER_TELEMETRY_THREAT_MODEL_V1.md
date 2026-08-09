# Developer telemetry threat model v1

## Assets

Collector keys, raw events, project mappings, private payloads, metering policies, sealed epochs,
proof witnesses, disclosure grants, and finalized anchor evidence are protected assets.

## Trust boundaries

| Component | Trusted for | Not trusted for |
| --- | --- | --- |
| Coding agent/plugin | Proposing bounded observations | Human presence, project identity, signing, retention, disclosure, settlement |
| IDE/terminal/Git adapters | Source-specific observations | Cross-source attribution or claims |
| Local collector | Authorization, sequencing, signing, retention, epoch construction | Consensus finality or remote verifier policy |
| Actum RPC/anchor registry | Durable submission and finalized evidence | Raw evidence, claim derivation, app presentation |
| PQ-ZK verifier | Exact published relation and journal | Collector authenticity or chain finality |
| Web app/explorer | Presentation and transport | Proof validity, wallet authority, hidden success callbacks |

## Required defenses

- Prompt injection cannot enable categories, resume collection, disclose evidence, delete data,
  sign epochs, or settle value.
- Events bind collector/project/sequence/time/source/subject/payload/authorization revision.
- Collector sequence and atomic journals prevent replay, forked history, rollback, and crash gaps.
- Monotonic time determines durations; wall-clock changes are recorded but do not create work.
- Human evidence requires local interaction assurance and idle segmentation; synthetic agent events
  cannot mint attention.
- Project IDs are keyed commitments. Repository remotes, paths, client names, and branch names are
  not public identifiers.
- Commit/artifact linkage uses exact cryptographic digests and records dirty-tree state separately.
- Model token claims bind provider/model/accounting revision and distinguish measured from
  estimated counters.
- Epoch trees reject duplicate leaves, sequence gaps, reordered events, substitution, and empty
  epochs.
- Anchor verification pins chain ID, genesis commitment, protocol revision, verifier revision,
  transaction, finalized block, and exact statement.
- Non-overlap proofs bind all compared intervals and policy revision; hidden client identity does
  not weaken interval completeness.
- Verification APIs are bounded, rate-limited, versioned, and fail closed. Unknown proof kinds and
  stale finality are not success.
- Logs exclude raw prompts, source, diffs, credentials, keys, private intervals, and client names.

## Abuse cases

The qualification suite must cover forged human presence, agent self-report inflation, clock
rollback, sequence reuse, project substitution, cherry-pick/rebase artifact ambiguity, concurrent
agents, overlapping projects, policy substitution, hidden interval omission, duplicate billing,
malformed signatures, stale anchors, wrong chain/genesis, proof replay, disclosure escalation,
retention bypass, interrupted deletion, collector restore/clone, and compromised web presentation.

## Explicit non-goals

V1 does not prove subjective quality, authorship, employment status, legal entitlement to payment,
or that unobserved work did not occur. Settlement remains a separate authorized application action.
