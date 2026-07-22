# Epoch, validator-set, and protocol-upgrade proof scope

Status: development proof model; not whole-protocol certification.

`formal/lean/ActiveChain/EpochUpgrade.lean` is the executable Lean 4 safety model for finalized
validator-set changes, epoch advancement, protocol-revision activation, and active certificate
context checks. It strengthens the P-110 light-client requirements into an explicit state-machine
contract that the consensus runtime and verifier must refine.

## Mechanically checked properties

Lean checks that:

- every accepted transition advances exactly one finalized height;
- changing a validator set requires authorization finalized at or before the current head and
  strictly before its declared activation height;
- validator-set activation happens at exactly the declared height, binds the previous and next
  roots, and advances to exactly the next epoch;
- changing a protocol revision requires the same prior-finalization and exact-height conditions;
- protocol revisions increase strictly when changed, while unchanged revisions remain valid;
- accepted state never decreases in height, epoch, or revision;
- a missed activation height is rejected rather than applied late;
- a retired validator-set root cannot be reactivated;
- certificates carrying a stale epoch, non-active validator-set root, or downgraded revision are
  rejected by the active context gate; and
- rollback attempts through epoch or revision downgrade are rejected.

The model contains no unchecked proof escape hatches or additional logical assumptions.

## Implementation mapping

| Model element | Rust/specification boundary |
| --- | --- |
| `ValidatorSetAuthorization` | canonical `ConsensusUpgradeAuthorization` plus its QC-certified commitment proof |
| consecutive `fromEpoch`/`toEpoch` | `ConsensusUpgradeAuthorization::new` in `crates/protocol-types/src/consensus.rs` |
| validator root binding | `ValidatorGenesis::validator_set_root` and `ConsensusState::validator_set_root` |
| `advance` | `ValidatorEngine::activate_finalized_validator_set` and durable snapshot update |
| `verifyCertificateContext` | epoch/root checks in `ValidatorEngine::apply_certificate`, extended with revision binding |
| `ProtocolUpgradeAuthorization` | the revision fields of `ConsensusUpgradeAuthorization`, verified against a finalized authorization block before exact-height activation |
| retired roots | bounded, canonical `ConsensusSnapshot` history; exhaustion and reactivation both fail closed |
| executable refinement | `epoch-upgrade-model-table.txt`, emitted independently by production Rust and `EpochUpgradeTable.lean` and compared byte-for-byte in CI |

## Assumptions and refinement boundary

- A `finalized = true` authorization is a trusted observation from the consensus finality kernel.
  This model proves activation rules after that observation; the Tamarin consensus model and Rust
  conformance tests must establish that the observation cannot be forged.
- Natural-number heights, epochs, and revisions abstract checked `u64` arithmetic. Rust must reject
  overflow and preserve the same ordering at its bounded representation.
- Validator-set roots and revision identifiers are abstract values. Collision and second-preimage
  resistance of their concrete domain-separated hashes is a cryptographic assumption outside Lean.
- The retired-root list is durable and complete. Snapshot rollback, storage corruption, recovery,
  and validator-set history synchronization require separate implementation and operational proofs.
- The model is a safety model. It does not prove that governance schedules an upgrade, that nodes
  remain available at activation, or that heterogeneous clients upgrade in time.
- Package-manifest compatibility, schema migration, execution semantics, and retained historical
  verification rules remain separate proof obligations.

## Rust conformance result and remaining boundary

The runtime now verifies a prior QC-certified authorization commitment, activates only at the exact
next height, checks the next genesis activation/root/revision, atomically replaces validator keys,
binds votes and QCs to the active revision, and durably rejects retired-root reuse or bounded-history
exhaustion. The checked differential matrix exercises validator-only, revision-only, combined,
wrong-height, stale-context, downgrade, retired-root, and 64-entry history-full cases through both
the Rust transition and Lean `advance`.

This is a bounded executable refinement, not a proof that arbitrary Rust executions simulate every
Lean natural-number state. QC unforgeability, snapshot rollback resistance, governance validity,
and heterogeneous-client deployment remain separate assumptions and operational gates.

## Local reproduction

```bash
(cd formal/lean && lake env lean ActiveChain/EpochUpgrade.lean)
(cd formal/lean && lake exe epochUpgradeTable)
cargo run --locked --quiet -p activechain-vector-generator -- epoch-upgrade-model-table
```

Acceptance requires a successful Lean run and a source scan confirming that the model contains no
unchecked proof placeholders or newly declared assumptions.
