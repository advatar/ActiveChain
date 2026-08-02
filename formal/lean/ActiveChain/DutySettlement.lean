/-!
# ActiveChain verifier duty settlement refinement model

This executable model covers the registration and settlement projection shared by accountable
verifier duties: one-shot settlement, exact bond conservation, bounded objective slashing, and
state preservation under every rejected settlement.

Cryptographic authorization of duty receipts, ML-DSA signature verification, principal identity
binding, and Coin Cell custody of the bond and reward are explicit production-boundary
assumptions.
-/

namespace ActiveChain.DutySettlement

structure Assignment where
  id : Nat
  verifier : Nat
  bondAmount : Nat
  reward : Nat
  deadline : Nat
  settled : Bool
  deriving BEq, DecidableEq, Inhabited, Repr

structure Receipt where
  assignment : Nat
  evidence : Nat
  height : Nat
  deriving BEq, DecidableEq, Inhabited, Repr

structure Fault where
  assignment : Nat
  slashAmount : Nat
  deriving BEq, DecidableEq, Inhabited, Repr

structure Settlement where
  assignment : Nat
  verifier : Nat
  reward : Nat
  bondReturn : Nat
  slashAmount : Nat
  deriving BEq, DecidableEq, Inhabited, Repr

abbrev State := List Assignment

/-- The production kernel resolves a receipt against the first registered assignment sharing its
identifier. -/
def lookup (state : State) (target : Nat) : Option Assignment :=
  state.find? (fun a => a.id == target)

/-- Registration rejects duplicate identifiers and degenerate bonds, rewards, or deadlines. -/
def register (state : State) (assignment : Assignment) : Option State :=
  if (lookup state assignment.id).isSome then
    none
  else if assignment.reward = 0 ∨ assignment.bondAmount = 0 ∨ assignment.deadline = 0 then
    none
  else
    some (state ++ [assignment])

/-- Settlement flips the settled flag of the addressed assignment and leaves every other field and
every other assignment untouched. -/
def markSettled (state : State) (target : Nat) : State :=
  state.map (fun a => if a.id = target then { a with settled := true } else a)

/-- An objective fault must reference the settled assignment and may not exceed its bond. -/
def faultIsValid (bondAmount assignmentId : Nat) (fault : Option Fault) : Bool :=
  match fault with
  | none => true
  | some f => f.assignment == assignmentId && f.slashAmount ≤ bondAmount

def slashAmount (fault : Option Fault) : Nat :=
  match fault with
  | none => 0
  | some f => f.slashAmount

/-- Settlement accepts only for the assigned verifier, only once, only with non-empty evidence,
only at or before the deadline, and only with a bounded fault against the same assignment. -/
def settle (state : State) (receipt : Receipt) (verifier : Nat) (fault : Option Fault) :
    Option (State × Settlement) :=
  match lookup state receipt.assignment with
  | none => none
  | some assignment =>
    if assignment.verifier = verifier ∧ assignment.settled = false ∧ receipt.evidence ≠ 0 ∧
        receipt.height ≤ assignment.deadline ∧
        faultIsValid assignment.bondAmount receipt.assignment fault = true then
      some
        (markSettled state receipt.assignment,
          { assignment := receipt.assignment
            verifier := verifier
            reward := assignment.reward
            bondReturn := assignment.bondAmount - slashAmount fault
            slashAmount := slashAmount fault })
    else
      none

/-- The state transition a node performs for a settlement attempt: a rejected attempt is a no-op. -/
def applySettle (state : State) (receipt : Receipt) (verifier : Nat) (fault : Option Fault) :
    State :=
  match settle state receipt verifier fault with
  | none => state
  | some (post, _) => post

def settledCount (state : State) : Nat :=
  (state.filter (fun a => a.settled)).length

theorem slashIsBoundedByValidFault
    (bondAmount assignmentId : Nat) (fault : Option Fault)
    (valid : faultIsValid bondAmount assignmentId fault = true) :
    slashAmount fault ≤ bondAmount := by
  cases fault with
  | none => simp [slashAmount]
  | some f =>
    simp only [faultIsValid, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at valid
    exact valid.2

/-- Marking an assignment settled preserves the identifier of every entry, so receipt resolution
still finds the same position. -/
theorem lookupMarkSettled (state : State) (target : Nat) :
    lookup (markSettled state target) target =
      (lookup state target).map (fun a => { a with settled := true }) := by
  induction state with
  | nil => rfl
  | cons head tail ih =>
    by_cases h : head.id = target
    · simp [lookup, markSettled, h]
    · simpa [lookup, markSettled, h] using ih

/-- Every accepted settlement records the assignment reward, a slash bounded by the bond, a bond
return of exactly the unslashed remainder, and the settled-flag state transition. -/
theorem settlementIsExact
    (pre post : State) (receipt : Receipt) (verifier : Nat) (fault : Option Fault)
    (assignment : Assignment) (settlement : Settlement)
    (found : lookup pre receipt.assignment = some assignment)
    (accepted : settle pre receipt verifier fault = some (post, settlement)) :
    settlement.slashAmount ≤ assignment.bondAmount ∧
      settlement.bondReturn = assignment.bondAmount - settlement.slashAmount ∧
      settlement.reward = assignment.reward ∧
      settlement.assignment = receipt.assignment ∧
      settlement.verifier = verifier ∧
      post = markSettled pre receipt.assignment := by
  simp only [settle, found] at accepted
  split at accepted
  case isTrue guard =>
    have pair := Option.some.inj accepted
    have postEq : markSettled pre receipt.assignment = post := congrArg Prod.fst pair
    have settlementEq :
        ({ assignment := receipt.assignment
           verifier := verifier
           reward := assignment.reward
           bondReturn := assignment.bondAmount - slashAmount fault
           slashAmount := slashAmount fault } : Settlement) = settlement :=
      congrArg Prod.snd pair
    subst settlementEq
    subst postEq
    exact ⟨slashIsBoundedByValidFault _ _ _ guard.2.2.2.2, rfl, rfl, rfl, rfl, rfl⟩
  case isFalse => exact absurd accepted (by simp)

/-- Theorem 1: settlement is one-shot. A second settlement of the same assignment is rejected and
therefore leaves the assignment list unchanged. -/
theorem settlementIsOneShot
    (pre post : State) (receipt second : Receipt) (verifier verifier' : Nat)
    (fault fault' : Option Fault) (settlement : Settlement)
    (accepted : settle pre receipt verifier fault = some (post, settlement))
    (sameAssignment : second.assignment = receipt.assignment) :
    settle post second verifier' fault' = none ∧
      applySettle post second verifier' fault' = post := by
  have replayRejected : settle post second verifier' fault' = none := by
    cases found : lookup pre receipt.assignment with
    | none => simp [settle, found] at accepted
    | some assignment =>
      obtain ⟨_, _, _, _, _, postEq⟩ := settlementIsExact pre post receipt verifier fault
        assignment settlement found accepted
      subst postEq
      have resolved :
          lookup (markSettled pre receipt.assignment) second.assignment =
            (lookup pre receipt.assignment).map (fun a => { a with settled := true }) := by
        rw [sameAssignment, lookupMarkSettled]
      simp [settle, resolved, found]
  exact ⟨replayRejected, by simp [applySettle, replayRejected]⟩

/-- Theorem 2: bonds are exactly conserved. An accepted settlement returns the whole bond, split
into the returned part and the slashed part, with no value created or destroyed. -/
theorem bondIsConserved
    (pre post : State) (receipt : Receipt) (verifier : Nat) (fault : Option Fault)
    (assignment : Assignment) (settlement : Settlement)
    (found : lookup pre receipt.assignment = some assignment)
    (accepted : settle pre receipt verifier fault = some (post, settlement)) :
    settlement.bondReturn + settlement.slashAmount = assignment.bondAmount := by
  obtain ⟨bounded, returnEq, _⟩ :=
    settlementIsExact pre post receipt verifier fault assignment settlement found accepted
  omega

/-- Theorem 3: slashing is bounded by the posted bond. -/
theorem slashIsBounded
    (pre post : State) (receipt : Receipt) (verifier : Nat) (fault : Option Fault)
    (assignment : Assignment) (settlement : Settlement)
    (found : lookup pre receipt.assignment = some assignment)
    (accepted : settle pre receipt verifier fault = some (post, settlement)) :
    settlement.slashAmount ≤ assignment.bondAmount :=
  (settlementIsExact pre post receipt verifier fault assignment settlement found accepted).1

/-- Theorem 4: a rejected settlement leaves the assignment list byte-identical. -/
theorem rejectedSettlementPreservesState
    (state : State) (receipt : Receipt) (verifier : Nat) (fault : Option Fault)
    (rejected : settle state receipt verifier fault = none) :
    applySettle state receipt verifier fault = state := by
  simp [applySettle, rejected]

/-- Registration is one-shot per identifier: re-registering a known assignment is rejected. -/
theorem registrationRejectsDuplicateIdentifiers
    (state : State) (assignment first : Assignment)
    (known : lookup state assignment.id = some first) :
    register state assignment = none := by
  simp [register, known]

/-- A settlement past the deadline is always rejected. -/
theorem expiredSettlementIsRejected
    (state : State) (receipt : Receipt) (verifier : Nat) (fault : Option Fault)
    (assignment : Assignment)
    (found : lookup state receipt.assignment = some assignment)
    (expired : assignment.deadline < receipt.height) :
    settle state receipt verifier fault = none := by
  simp only [settle, found]
  split
  case isTrue guard => omega
  case isFalse => rfl

/-- Only the assigned verifier can settle a duty. -/
theorem wrongVerifierSettlementIsRejected
    (state : State) (receipt : Receipt) (verifier : Nat) (fault : Option Fault)
    (assignment : Assignment)
    (found : lookup state receipt.assignment = some assignment)
    (mismatch : assignment.verifier ≠ verifier) :
    settle state receipt verifier fault = none := by
  simp only [settle, found]
  split
  case isTrue guard => exact absurd guard.1 mismatch
  case isFalse => rfl

/-- Empty evidence never settles a duty. -/
theorem emptyEvidenceSettlementIsRejected
    (state : State) (receipt : Receipt) (verifier : Nat) (fault : Option Fault)
    (assignment : Assignment)
    (found : lookup state receipt.assignment = some assignment)
    (empty : receipt.evidence = 0) :
    settle state receipt verifier fault = none := by
  simp only [settle, found]
  split
  case isTrue guard => exact absurd empty guard.2.2.1
  case isFalse => rfl

/-- Settlement never adds, removes, or reorders assignments, and never rewrites a bond, reward,
deadline, verifier, or identifier. -/
theorem settlementPreservesAssignmentRegistry
    (state : State) (receipt : Receipt) (verifier : Nat) (fault : Option Fault) :
    (applySettle state receipt verifier fault).map
        (fun a => (a.id, a.verifier, a.bondAmount, a.reward, a.deadline)) =
      state.map (fun a => (a.id, a.verifier, a.bondAmount, a.reward, a.deadline)) := by
  unfold applySettle
  split
  case h_1 => rfl
  case h_2 post settlement accepted =>
    cases found : lookup state receipt.assignment with
    | none => simp [settle, found] at accepted
    | some assignment =>
      obtain ⟨_, _, _, _, _, postEq⟩ := settlementIsExact state post receipt verifier fault
        assignment settlement found accepted
      subst postEq
      simp only [markSettled, List.map_map]
      apply List.map_congr_left
      intro a _
      by_cases h : a.id = receipt.assignment <;> simp [h]

end ActiveChain.DutySettlement
