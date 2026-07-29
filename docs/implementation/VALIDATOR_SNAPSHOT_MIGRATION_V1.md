# Validator snapshot migration and rebuild v1

The current persisted validator safety-state schema is version 5. Unlike schema 4, every retained
certified-history entry contains the complete signed proposal, quorum certificate, and ordered
signed vote proof. Validators reverify those proofs against the active genesis manifest during
restart before using them as proposal ancestry.

Schema-4 migration is deliberately bounded. A structurally valid schema-4 snapshot with no
retained certified history is rewritten atomically as schema 5 during service startup. A schema-4
snapshot whose old reduced records cannot decode as complete proofs is rejected and requires the
recoverable archive-and-genesis rebuild procedure below; the validator never synthesizes missing
proposal signatures or vote evidence.

When a live peer is missing retained ancestry, it requests the exact proposal commitment through
an ML-DSA-authenticated `CertifiedBlockRequest`. The serving validator admits the request sequence
durably before lookup, returns the complete `Certificate` proof in a separately authenticated
response, and reserves the response sequence durably before signing. Unknown or pruned history is
an explicit error; replayed requests/responses and digest-mismatched bodies fail closed, including
after either validator restarts.

Validator snapshots are consensus safety state, not ordinary application data. An incompatible
schema or genesis commitment must never be decoded heuristically or overwritten in place.

## Promotion gate

Before installing a binary, operators run:

```sh
ACTIVECHAIN_EXPECTED_SNAPSHOT_SCHEMA_VERSION=1 \
ACTIVECHAIN_EXPECTED_GENESIS_COMMITMENT="$GENESIS_COMMITMENT" \
  scripts/check-validator-snapshot.sh "$STATE_ROOT/validator-0.snapshot" \
  "$RELEASE_ROOT/bin/indexer-tool"
```

The check must pass for every validator snapshot. A missing immutable genesis commitment is
incompatible with the current safety format and is not upgraded in place.

## Rebuild procedure

1. Stop the validator and RPC/indexer processes and acquire the deployment lock.
2. Copy the complete state directory to an offline, access-controlled backup, including the
   genesis manifest, validator keys, validator snapshot, RPC index, and cash/finality artifacts.
3. Record the old snapshot schema, genesis commitment, finalized height, binary digest, and UTC
   timestamp in the change log.
4. Verify the intended genesis commitment and release checksums independently.
5. Move the incompatible snapshot to an immutable backup name; never delete or overwrite it.
6. Recreate a fresh validator snapshot from the exact intended genesis manifest using the release
   `validator-node` bootstrap path.
7. Rebuild the RPC index from the fresh validator snapshot. Re-ingest a cash snapshot only when
   its chain genesis, finalized height, cash root, and finality bundle verify together.
8. Run the local authenticated quorum rehearsal and the remote canary before enabling public RPC.
9. Keep the old backup until the release council's retention period and incident-review window
   expire.

No migration may carry forward votes, locks, replay high-water marks, or certified ancestry from
an incompatible snapshot. Those values are safety-critical and must be regenerated from the
new genesis and finalized history.
