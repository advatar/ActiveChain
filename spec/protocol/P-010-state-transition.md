# P-010: Global state-transition function

- Status: Skeleton draft 0.1
- Protocol version: Development

## 1. Scope

This document fixes the interface and invariants that canonical types must refine. The executable transition is intentionally deferred until principal, capability, policy, and object semantics are specified.

## 2. Normative interface

```text
transition(
    pre_state_commitment,
    canonical_block,
    state_witness,
    protocol_version
) -> TransitionOutput | TransitionError
```

For identical inputs, conforming implementations MUST return byte-identical outputs or the same typed error. The function MUST NOT read a clock, filesystem, network, environment variable, random device, locale, or floating-point state.

## 3. Transition output

A future `TransitionOutput` MUST bind at least the post-state root, receipt root, event root, resource usage, fee changes, capability-budget changes, and nullifier changes. It MUST also expose the deterministic trace material required by the proof system.

## 4. State-machine outline

```text
decode and version-check all inputs
verify the witness opens the declared pre-state
for each envelope in canonical order:
    authenticate the actor or private actor commitment
    validate capability chains and mutable budgets
    evaluate credential, object, and contract policies
    validate object versions and declared access
    execute commands or produce a deterministic failure receipt
    account for resources and fees
atomically commit successful effects
derive roots and the execution trace
```

No failed transaction may leave partial effects. A malformed but admitted envelope MUST have a total, provable outcome.

## 5. Error behavior

Errors before transaction admission reject the candidate transition. Per-envelope semantic failures after admission become canonical receipts. Protocol-version dispatch MUST define which class each error belongs to.

## 6. Resource bounds

The block, witness, transaction count, object accesses, policy work, VM work, event bytes, created objects, and trace units MUST each have independent versioned maxima. No implementation may replace these with an unbounded host allocation.

## 7. Security assumptions

This function trusts only the protocol-version dispatcher, canonical decoder, cryptographic verifiers, state-root computation, authorization kernel, ObjectVM semantics, and proof verifier. Operating-system adapters and persistence engines are outside its semantic trusted base.

## 8. Test vectors and formal properties

Initial vectors cover only canonical inputs. Later revisions MUST add success, every failure receipt, replay, stale versions, atomic abort, authorization denial, fee accounting, and cross-client state-root vectors.

Required properties include determinism, atomicity, access confinement, object uniqueness, resource conservation, budget safety, replay freedom, and proof-input binding.

## 9. Compatibility

Every transition is dispatched by an explicit protocol version. An upgrade MUST preserve historical verification and MUST define activation behavior, migrations, and unsupported-version errors.

## 10. Implementation notes (non-normative)

The production Rust function will live in a `no_std` transition crate. Node, prover, simulator, and light-client adapters will invoke the same typed boundary without adding ambient inputs.
