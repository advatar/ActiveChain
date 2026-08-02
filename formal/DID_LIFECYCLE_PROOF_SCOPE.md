# DID controller lifecycle refinement proof scope

Status: mechanically checked bounded model and Rust/Lean differential trace; not whole-system
certification.

`formal/lean/ActiveChain/DidLifecycle.lean` proves that `did:activechain` controller creation
requires a fresh identity, that every accepted update, recover, and deactivate strictly increases
the record sequence, that every such operation binds the exact current record commitment (and that
a stale or foreign previous commitment is refused), that deactivation is terminal, that a control
authenticator can never authorize a recovery (and a recovery authenticator can never authorize an
update or a deactivation), and that every rejected operation leaves the controller registry
byte-identical.

The production `DidControllerOperationV1::new` and
`DidControllerRecordV1::apply_document_operation` in `crates/protocol-types/src/did.rs`
independently perform the real well-formedness checks, document commitment matching, checked
sequence successor arithmetic, previous-commitment binding, authorizer resolution, and purpose
gating. Their observable projection — registered controller count, active controller count, and the
sequence of the tracked controller — must match `formal/lean/DidLifecycleTable.lean`
byte-for-byte.

## Assumed at the production boundary

- Commitment collision resistance. The model represents the SHAKE-256 record commitment by the
  record it commits to; it does not prove that distinct records cannot share a commitment.
- ML-DSA / SLH-DSA signature verification. `DidOperationAuthorizationV1` unforgeability, chain
  genesis binding, and custody of the signing key are assumed, not proved. The model takes the
  named authorizer as an already authenticated input and proves only the purpose gate.
- Canonical encoding. Envelope encoding, length prefixes, and decode-side revalidation are covered
  by the separate codec scope, not here.
- Authenticator validity windows. `AuthenticatorDescriptor::is_active_at` height gating and
  revocation heights are not modeled; the refinement trace pins every method to an open window.
- Key-agreement material. ML-KEM public keys, document service commitments, and method ordering
  constraints are enforced by `DidDocumentV1::new` and are outside the lifecycle model.
- Bounded arithmetic. Sequences are unbounded `Nat`; `u64` width, wraparound, and ceiling behavior
  are not modeled and are checked on the production side only.
- Registry storage. The controller registry is an in-memory sequential list. Finalized state-tree
  storage, resolver anti-rollback checkpoints (`DidResolutionCheckpointV1`), durability, and
  concurrency are out of scope.

## Proved

- `createRequiresFreshIdentity` — an accepted create carries no previous commitment, starts at
  sequence 1, leaves the record active, stays on its own principal, applies only to an unregistered
  principal, and extends the registry by exactly that record.
- `sequenceIsStrictlyMonotone` — every accepted update, recover, or deactivate resolves to the
  successor record and strictly increases the sequence. Sequences are unbounded `Nat` here, so the
  model states the property but cannot itself witness the `u64` ceiling: the `saturating_add(1)`
  defect fixed by [#683](https://github.com/advatar/ActiveChain/issues/683) is a bounded-width
  refutation, and the production side of it stays covered by the
  `sequence_successor_fails_closed_at_the_u64_ceiling` regression test. With the `checked_add(1)`
  successor in place, the production rule now refines the unbounded model unconditionally.
- `operationBindsPreviousCommitment` — an accepted update, recover, or deactivate binds exactly the
  current record commitment.
- `staleOrForeignCommitmentIsRejected` — an operation carrying any other previous commitment is
  refused and the applied transition is the identity.
- `deactivationIsTerminal` — after an accepted deactivate, no operation of any kind on that
  principal, under any authorizer, is ever accepted again.
- `rejectedOperationsPreserveState` — a rejected operation is a registry no-op.
- `controlCannotAuthorizeRecovery` and `recoveryCannotAuthorizeUpdateOrDeactivate` — the purpose
  gate of `apply_document_operation` is exact in both directions.
- `transitionIsExact`, `createRejectsRegisteredIdentity`, `inactiveRecordSurvivesOneStep`, and
  `inactiveRecordSurvivesEveryTrace` (terminality under an arbitrary trace, by induction).

Every theorem is fully proved; the module contains no `sorry`, no `axiom`, and no `native_decide`.

Run the focused gate with:

```sh
bash scripts/check-did-lifecycle-refinement.sh
```
