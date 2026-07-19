# P-020: Principal lifecycle and controller authentication

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/2>

## 1. Scope

This revision specifies principal creation, controller rotation, freeze, and recovery initiation. Recovery challenge, cancellation, and completion will be extended without changing the canonical operations defined here.

## 2. Principal creation

Creation receives a `PrincipalGenesis`, block height, and protocol-version minimum anchor deposit. It MUST reject a deposit below the minimum. A successful principal has:

```text
sequence = 0
freeze_state = Active
created_at = height
last_updated_at = height
```

The identifier MUST be independent of controller keys so rotation does not change identity.

## 3. Pre-verified lifecycle authorization

The lifecycle state machine consumes a fact bound to:

```text
authority_kind = Controller | Recovery
principal_id
principal_sequence
policy_hash
```

This fact is not itself a proof. Consensus code MUST construct it only after actor authentication and deterministic evaluation of the named policy against the same committed state. The lifecycle machine MUST reject an absent fact or any principal, sequence, authority-kind, or policy-hash mismatch.

## 4. Commands

### 4.1 Rotate controller

Rotation requires `Active` state and current controller authority. It atomically replaces `controller_policy_hash` and `authenticator_set_root`, increments the sequence exactly once, and updates `last_updated_at`.

### 4.2 Freeze

Freeze requires `Active` state and current controller authority. It sets `freeze_state = Frozen`, increments the sequence exactly once, and preserves both policies and the authenticator root.

### 4.3 Initiate recovery

Recovery initiation requires current recovery authority and is permitted from `Active` or `Frozen`. It MUST be rejected from `RecoveryPending`.

The operation atomically:

1. creates a `RecoveryRequest` bound to the current principal and pre-transition sequence;
2. requires `challenge_deadline > initiation_height`;
3. commits the proposed controller policy, proposed authenticator root, recovery evidence, and bond;
4. sets the principal to `RecoveryPending`;
5. increments the principal sequence exactly once.

The current controller is not replaced during initiation.

## 5. State-machine pseudocode

```text
apply(principal, command, authorization, height):
    require height >= principal.last_updated_at
    require command.expected_sequence == principal.sequence
    require command is permitted by principal.freeze_state
    require authorization is present
    require authorization binds principal.id and principal.sequence
    require authorization kind and policy hash match the command
    next_sequence = checked_add(principal.sequence, 1)
    return the atomic updated principal and optional recovery request
```

Validation order above is normative for deterministic error selection.

## 6. Errors and abort behavior

Errors include insufficient anchor deposit, height regression, stale sequence, sequence exhaustion, missing or mismatched authorization, wrong authority kind, wrong policy commitment, controller operation outside `Active`, duplicate pending recovery, invalid challenge deadline, and invalid result construction.

Every error aborts with no principal or recovery-request update.

## 7. Resource bounds

All operations are constant-time with respect to collection sizes and allocate no unbounded memory. `PrincipalV1` is 282 bytes and `RecoveryRequestV1` is 232 bytes before their top-level envelope headers.

## 8. Security assumptions

Safety requires the upstream authorization kernel to authenticate the actor, verify signatures or private proofs, evaluate the committed policy, and emit the exact lifecycle authorization fact. Supplying an unverified fact to this state machine would violate the protocol boundary.

## 9. Test vectors and formal properties

Authority vectors cover genesis, controller rotation, freeze, and recovery initiation. Required properties are stable identity, monotonic height, one-step sequence consumption, replay rejection, controller-policy binding, recovery-policy separation, and atomic creation of recovery state.

Property tests MUST cover every non-exhausted sequence value. Future Lean refinement MUST prove that no successful command preserves or decreases the sequence.

## 10. Compatibility

New lifecycle commands require a new protocol version or unused command tag. Existing command error order and output fields MUST NOT change retroactively. Recovery completion rules may extend the state machine while preserving initiation semantics.

## 11. Implementation notes (non-normative)

The reference implementation is a safe-Rust `no_std` crate with no clock, cryptography, storage, or network dependency.
