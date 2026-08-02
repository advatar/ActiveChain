# Verifier duty settlement refinement proof scope

Status: mechanically checked bounded model and Rust/Lean differential trace; not whole-system
certification.

`formal/lean/ActiveChain/DutySettlement.lean` proves that duty settlement is one-shot, that an
accepted settlement conserves the posted bond exactly (`bond_return + slash = bond`), that slashing
is bounded by the bond, and that every rejected settlement leaves the assignment registry
byte-identical. It additionally proves that registration rejects duplicate assignment identifiers,
that expired, wrong-verifier, and empty-evidence receipts never settle, and that settlement never
adds, removes, reorders, or rewrites the identifier, verifier, bond, reward, or deadline of any
registered assignment.

The production `register_assignment`/`settle_duty` kernel in `crates/cash-kernel/src/economics.rs`
independently performs real assignment registration, duplicate rejection, one-shot settlement,
bounded objective faulting, deadline enforcement, verifier binding, and empty-evidence rejection.
Its observable projection — registered count, settled count, reward, bond return, and slash amount
— must match `DutySettlementTable.lean` byte-for-byte.

## Assumed at the production boundary

- Cryptographic authorization of duty receipts. The model takes the receipt as an already
  authenticated input and does not prove that only the assigned verifier can produce one.
- ML-DSA signature verification. Unforgeability of the signatures that gate settlement ingress is
  assumed, not proved.
- Principal identity. `PrincipalId` equality is modeled as identifier equality; the model does not
  prove that a principal identifier is bound to a unique real controller, nor that finalized
  identity state was consulted.
- Objective fault adjudication. The model checks that a fault references the settled assignment and
  is bounded by the bond; it does not prove that the fault evidence actually demonstrates
  misbehavior.
- Coin Cell custody. The model tracks bond and reward as `Nat` amounts. Movement of the returned
  bond, the slashed portion, and the reward into real Coin Cells is covered by the separate cash
  lifecycle scope, not here.
- Durability, concurrency, and block-level finality binding. The trace is a single sequential
  in-memory registry; filesystem durability, concurrent batches, and finality admission are out of
  scope.

## Proved

- `settlementIsOneShot` — a second settlement of an already-settled assignment returns `none` and
  the applied state transition is the identity.
- `bondIsConserved` — `bondReturn + slashAmount = bondAmount` on every acceptance.
- `slashIsBounded` — `slashAmount ≤ bondAmount` on every acceptance.
- `rejectedSettlementPreservesState` — a rejected settlement is a state no-op.
- `settlementIsExact`, `registrationRejectsDuplicateIdentifiers`, `expiredSettlementIsRejected`,
  `wrongVerifierSettlementIsRejected`, `emptyEvidenceSettlementIsRejected`, and
  `settlementPreservesAssignmentRegistry`.

Every theorem is fully proved; the module contains no `sorry`, no `axiom`, and no `native_decide`.

Run the focused gate with:

```sh
bash scripts/check-duty-settlement-refinement.sh
```
