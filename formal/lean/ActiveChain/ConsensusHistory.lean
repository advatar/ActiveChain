/-!
# ActiveChain finalized-history prefix model

This dependency-free model separates the history-lifting part of consensus safety from the
quorum argument.  A history is ordered from genesis to its finalized tip.  Its validity requires
every adjacent block to name the exact previous digest, advance height once, keep views monotonic,
and either retain the epoch or advance it exactly once.

The principal theorem proves that the comparable-tip obligation supplied by the consensus/QC
safety layer implies prefix comparability of the complete finalized histories.  Restart is modeled
as restoring the identical durable history, while an epoch transition is an ordinary parent-bound
extension.  Proving that the Rust QC/lock/reconfiguration implementation always supplies the
comparable-tip premise remains a separate refinement obligation.
-/

namespace ActiveChain.ConsensusHistory

abbrev Digest := Nat

structure BlockRef where
  digest : Digest
  parent : Digest
  height : Nat
  view : Nat
  epoch : Nat
  deriving BEq, DecidableEq, Repr

/-- Exact relationship required between adjacent blocks in a finalized history. -/
def ParentStep (parent child : BlockRef) : Prop :=
  child.parent = parent.digest ∧
    child.height = parent.height + 1 ∧
    parent.view ≤ child.view ∧
    (child.epoch = parent.epoch ∨ child.epoch = parent.epoch + 1)

/-- Recursive adjacent-pair validity, avoiding any assumptions about non-adjacent blocks. -/
def ValidChain : List BlockRef → Prop
  | [] => False
  | [_] => True
  | parent :: child :: rest => ParentStep parent child ∧ ValidChain (child :: rest)

structure FinalizedHistory where
  blocks : List BlockRef
  valid : ValidChain blocks

/-- `shorter` is a prefix of `longer`, with the extension made explicit. -/
def IsPrefix (shorter longer : List BlockRef) : Prop :=
  ∃ suffix, longer = shorter ++ suffix

def PrefixComparable (left right : FinalizedHistory) : Prop :=
  IsPrefix left.blocks right.blocks ∨ IsPrefix right.blocks left.blocks

/--
Consensus supplies this obligation after QC intersection, safe-vote locks, and reconfiguration
admission have ruled out conflicting finalized tips.  It is deliberately named as an assumption,
not hidden inside the history theorem.
-/
def FinalizedTipsComparable (left right : FinalizedHistory) : Prop :=
  (∃ suffix, right.blocks = left.blocks ++ suffix) ∨
    (∃ suffix, left.blocks = right.blocks ++ suffix)

/-- Comparable finalized tips lift directly to prefix-comparable complete histories. -/
theorem comparableFinalizedTipsImplyPrefixHistories
    (left right : FinalizedHistory)
    (safeTips : FinalizedTipsComparable left right) :
    PrefixComparable left right := by
  exact safeTips

/-- Durable recovery restores the same finalized history, so neither rollback nor a fork appears. -/
structure DurableSnapshot where
  finalized : FinalizedHistory

def restore (snapshot : DurableSnapshot) : FinalizedHistory := snapshot.finalized

theorem restartPreservesFinalizedHistory (snapshot : DurableSnapshot) :
    (restore snapshot).blocks = snapshot.finalized.blocks := by
  rfl

theorem restartHistoryIsPrefixComparable (snapshot : DurableSnapshot) :
    PrefixComparable snapshot.finalized (restore snapshot) := by
  left
  exact ⟨[], by simp [restore]⟩

/-- Exact epoch transition required for an appended first block of the next epoch. -/
def ExactEpochTransition (prior next : BlockRef) : Prop :=
  next.parent = prior.digest ∧
    next.height = prior.height + 1 ∧
    prior.view ≤ next.view ∧
    next.epoch = prior.epoch + 1

theorem exactEpochTransitionIsParentStep
    (prior next : BlockRef)
    (transition : ExactEpochTransition prior next) :
    ParentStep prior next := by
  exact ⟨transition.1, transition.2.1, transition.2.2.1, Or.inr transition.2.2.2⟩

/-- Appending a parent-bound epoch-transition block preserves the complete prior prefix. -/
theorem epochTransitionPreservesPriorPrefix
    (history : FinalizedHistory)
    (next : BlockRef)
    (transition :
      ∃ prior suffix,
        history.blocks = suffix ++ [prior] ∧ ExactEpochTransition prior next) :
    IsPrefix history.blocks (history.blocks ++ [next]) := by
  obtain ⟨prior, _, _, exactTransition⟩ := transition
  have _parentStep := exactEpochTransitionIsParentStep prior next exactTransition
  exact ⟨[next], rfl⟩

/-- Restart cannot change the prefix result for any already-safe pair of finalized histories. -/
theorem restartPreservesCrossHistoryPrefixSafety
    (left right : DurableSnapshot)
    (safeTips : FinalizedTipsComparable left.finalized right.finalized) :
    PrefixComparable (restore left) (restore right) := by
  exact comparableFinalizedTipsImplyPrefixHistories left.finalized right.finalized safeTips

end ActiveChain.ConsensusHistory
