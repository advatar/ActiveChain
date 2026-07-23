# Browser and agent application primitives

`activechain-application-primitives` is the revisioned downstream boundary for browser jobs,
delegated agents, AFMarket-style execution, and finalized application receipts.

Revision 1 publishes six bounded canonical values:

| Value | Type tag | Binding |
| --- | ---: | --- |
| `Artifact` | `0x00c0` | bytes, media type, producer, and provenance |
| `ApplicationManifest` | `0x00c1` | chain, application revision, entrypoint, artifacts, resources, and fee ceiling |
| `DelegatedAction` | `0x00c2` | job, chain, requester, executor, capability, sequence, validity, manifest, input, and fee ceiling |
| `ExecutionEvidence` | `0x00c3` | delegated action, executor, results, artifacts, provenance, resource use, and completion height |
| `ApplicationReceipt` | `0x00c4` | terminal status, evidence, exactly-once fee charge, finality height, and replay domain |
| job-ledger snapshot | `0x00c5` | active jobs, replay high-water marks, and terminal receipts |

The job ledger admits a delegation only when its chain, manifest commitment, executor/capability,
validity window, sequence, and fee bound match. Completion additionally binds the exact delegated
action commitment, executor, evidence, resource use, fee, and deadline. Cancellation and timeout
are terminal, and no terminal job can settle again.

`DurableJobLedger` writes canonical snapshots through a temporary file, synchronizes the file,
renames it atomically, and synchronizes the parent directory. A failed publication restores the
pre-operation in-memory state. Restart decoding rejects corrupt, unordered, overlapping, or
internally substituted job state.

## Finalized lookup

RPC schema revision 1 reserves `QueryKind::ApplicationReceipt`. The value is the canonical
application receipt, the lookup key is its `JobId`, and the height is the receipt's finalization
height. Its ordered-set proof must contain the receipt commitment and reproduce the finalized
header's action root. The existing finality verifier authenticates that header and validator
quorum. Clients must run the complete `rpc-server::verify_query_record` or equivalent light-client
checks; application-only framing validation is not a substitute for finality verification.

## Failure vectors

The crate and RPC tests freeze positive and negative behavior for canonical round trips, duplicate
jobs and sequences, wrong capability holders, cancellation authority, premature timeout, evidence
or executor substitution, resource and fee excess, exactly-once settlement, restart recovery,
snapshot corruption, wrong lookup keys/heights, missing proof material, and substituted finalized
ordered sets.

This boundary is developmental and unaudited. It does not make delegated browser execution safe
for production value until the external audit gate in `docs/SECURITY_AUDIT.md` completes.
