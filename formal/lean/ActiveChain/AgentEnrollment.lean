/-!
# ActiveChain agent-enrollment lifecycle model

This model fixes the monotonic evidence transition accepted by wallet-core. Cryptographic
authenticity and the Rust-to-Lean serialization refinement remain external assumptions.
-/

namespace ActiveChain.AgentEnrollment

inductive Outcome where
  | submitted (transaction : Nat)
  | finalized (transaction finalizedHeight blockCommitment inclusionCommitment : Nat)
  | rejected (observedHeight reason : Nat)
  | expired (observedHeight : Nat)
  deriving BEq, DecidableEq, Repr

def wellFormed : Outcome → Bool
  | .submitted transaction => transaction != 0
  | .finalized transaction height block inclusion =>
      transaction != 0 && height != 0 && block != 0 && inclusion != 0
  | .rejected height _ => height != 0
  | .expired height => height != 0

def follows (previous next : Outcome) : Bool :=
  if previous = next then true
  else
    match previous, next with
    | .submitted expected, .finalized transaction _ _ _ => expected = transaction
    | .submitted _, .rejected _ _ => true
    | .submitted _, .expired _ => true
    | _, _ => false

def isTerminal : Outcome → Bool
  | .submitted _ => false
  | .finalized _ _ _ _ | .rejected _ _ | .expired _ => true

theorem terminalIsImmutable
    (terminal next : Outcome)
    (hTerminal : isTerminal terminal = true)
    (h : follows terminal next = true) :
    next = terminal := by
  cases terminal <;> cases next <;> simp_all [isTerminal, follows]

theorem finalizationKeepsExactTransaction
    (expected transaction height block inclusion : Nat)
    (h : follows (.submitted expected)
      (.finalized transaction height block inclusion) = true) :
    transaction = expected := by
  by_cases same :
      Outcome.submitted expected = .finalized transaction height block inclusion
  · cases same
  · simp [follows, same] at h
    exact h.symm

@[simp] theorem submittedMayReject (transaction height reason : Nat) :
    follows (.submitted transaction) (.rejected height reason) = true := by
  simp [follows]

@[simp] theorem finalizedCannotExpire
    (transaction height block inclusion observed : Nat) :
    follows (.finalized transaction height block inclusion) (.expired observed) = false := by
  simp [follows]

end ActiveChain.AgentEnrollment
