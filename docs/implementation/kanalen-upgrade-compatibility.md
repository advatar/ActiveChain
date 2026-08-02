# Kanalen upgrade compatibility gate

Validator and RPC binaries must not be promoted solely because they compile. Before switching
`kanalen/current`, the release runner must inspect the persisted snapshot schema and run a
read-only decode check with the candidate binaries. A mismatch is a hard stop.

The 2026-07-25 canary of `origin/main` was safely rolled back: the candidate validator reported
`snapshot decoding failed` for the existing `validator-1.snapshot` and `validator-2.snapshot`.
The previous `cb738c6c00c50dd75e3d4ad4e7730b2cb25f7525` release was restored and all three launchd
services returned to running state. No state was overwritten.

Required follow-up: publish an explicit snapshot schema/version marker, add migration or clean
rebuild tooling, and rehearse rollback on a copy before the next promotion.

The candidate preflight is executable with `scripts/check-validator-snapshot.sh` and
`scripts/check-execution-snapshot.sh`; deployment must run them with the candidate `indexer-tool`
against every persisted validator snapshot and the execution snapshot before switching
`kanalen/current`. The execution check is read-only and reports whether the bounded migration path
will be required; migration is persisted atomically by validator startup only after the expected
chain and height match.
