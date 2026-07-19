/-!
# ActiveChain P-040 exact nonce-channel model

This executable model fixes replay, sequence-gap, and exhaustion precedence
independently of the Rust action and block kernels.
-/

namespace ActiveChain.Nonce

def maxSequence : Nat := 18446744073709551615

inductive AdvanceResult where
  | accepted (nextSequence : Nat)
  | replay
  | sequenceGap
  | sequenceExhausted
  deriving BEq, DecidableEq, Repr

def advance (expected supplied : Nat) : AdvanceResult :=
  if supplied < expected then
    .replay
  else if supplied > expected then
    .sequenceGap
  else if expected = maxSequence then
    .sequenceExhausted
  else
    .accepted (expected + 1)

theorem acceptedAdvancesExactlyOnce
    (expected supplied nextSequence : Nat)
    (h : advance expected supplied = .accepted nextSequence) :
    supplied = expected ∧ nextSequence = expected + 1 := by
  by_cases hReplay : supplied < expected
  · simp [advance, hReplay] at h
  · by_cases hGap : supplied > expected
    · simp [advance, hReplay, hGap] at h
    · have suppliedEq : supplied = expected :=
        Nat.le_antisymm (Nat.le_of_not_gt hGap) (Nat.le_of_not_gt hReplay)
      subst supplied
      by_cases exhausted : expected = maxSequence
      · simp [advance, exhausted] at h
      · simp [advance, exhausted] at h
        exact ⟨rfl, h.symm⟩

@[simp] theorem consumedSequenceIsReplay (next : Nat) :
    advance (next + 1) next = .replay := by
  simp [advance]

@[simp] theorem exhaustedSequenceCannotWrap :
    advance maxSequence maxSequence = .sequenceExhausted := by
  simp [advance]

def nonceCases : List (Nat × Nat) :=
  [
    (5, 5),
    (5, 4),
    (5, 6),
    (maxSequence, maxSequence)
  ]

def nonceTable : List (Nat × Nat × AdvanceResult) :=
  nonceCases.map fun (expected, supplied) =>
    (expected, supplied, advance expected supplied)

theorem nonceTableHasFourRows : nonceTable.length = 4 := rfl

end ActiveChain.Nonce
