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
| `ValidatorSetAuthorization` | `EpochTransition` plus its finalized on-chain authorization evidence |
| consecutive `fromEpoch`/`toEpoch` | `EpochTransition::new` in `crates/protocol-types/src/consensus.rs` |
| validator root binding | `ValidatorGenesis::validator_set_root` and `ConsensusState::validator_set_root` |
| `advance` | `ValidatorEngine::activate_finalized_validator_set` and durable snapshot update |
| `verifyCertificateContext` | epoch/root checks in `ValidatorEngine::apply_certificate`, extended with revision binding |
| `ProtocolUpgradeAuthorization` | P-110 finalized version gate; runtime implementation is still required |
| retired roots | durable validator-set history required by the light client and runtime |

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

## Rust conformance gaps exposed by the model

The checked contract is currently stronger than the implementation in these launch-critical areas:

1. `ValidatorEngine::activate_finalized_validator_set` accepts activation after
   `finalized_height >= activation_height`; it does not enforce execution at the exact height.
2. The engine does not require `next_genesis.activation_height()` to equal the transition's
   activation height.
3. The method accepts a caller-provided `EpochTransition` after a height check but does not verify a
   finalized on-chain authorization commitment for that exact transition.
4. Consensus state does not yet carry a protocol revision or a finalized revision-upgrade record.
5. Consensus snapshots do not retain validator-set-root history, so the runtime cannot reject an
   explicitly reintroduced retired root using durable history alone.
6. Certificate context checks bind epoch and validator-set root, but no runtime protocol-revision
   field exists to reject a downgrade at consensus admission.

These are implementation blockers, not properties proved about the deployed Rust node. The formal
result may be described as a verified activation contract only until each gap has conformance tests
and a traceable implementation mapping.

## Local reproduction

```bash
cd formal/lean
lake env lean ActiveChain/EpochUpgrade.lean
```

Acceptance requires a successful Lean run and a source scan confirming that the model contains no
unchecked proof placeholders or newly declared assumptions.
