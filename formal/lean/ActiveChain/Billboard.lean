/-!
# ActiveChain private-billboard transition model

Arithmetic and admission invariants for the post and withdrawal relations. Cryptographic
binding of commitments is an explicit boundary and is modeled by equality of digests.
-/

namespace ActiveChain.Billboard

abbrev Digest := Nat

structure Config where
  cooldownBase : Nat
  cooldownReductionPerUnit : Nat
  screeningPenalty : Nat

def cooldown (config : Config) (deposit : Nat) : Nat :=
  config.cooldownBase - deposit * config.cooldownReductionPerUnit

def postAmount (priorAmount fee : Nat) (flagged : Bool) (config : Config) : Option Nat :=
  let cost := fee + if flagged then config.screeningPenalty else 0
  if cost ≤ priorAmount then some (priorAmount - cost) else none

theorem postConservesValue (config : Config) (prior fee next : Nat) (flagged : Bool)
    (accepted : postAmount prior fee flagged config = some next) :
    next + fee + (if flagged then config.screeningPenalty else 0) = prior := by
  cases flagged <;> simp [postAmount] at accepted ⊢ <;> omega

theorem cooldownNeverExceedsBase (config : Config) (deposit : Nat) :
    cooldown config deposit ≤ config.cooldownBase := by
  simp [cooldown]

structure PostStatement where
  priorCommitment : Digest
  successorCommitment : Digest

structure PostWitness where
  priorCommitment : Digest
  successorCommitment : Digest

def successorBound (statement : PostStatement) (witness : PostWitness) : Bool :=
  statement.priorCommitment == witness.priorCommitment &&
    statement.successorCommitment == witness.successorCommitment

theorem acceptedBindsSuccessor (statement : PostStatement) (witness : PostWitness)
    (accepted : successorBound statement witness = true) :
    statement.successorCommitment = witness.successorCommitment := by
  simp [successorBound] at accepted
  exact accepted.2

structure AdmissionState where
  spent : List Digest
  permits : List Digest
  deriving BEq, DecidableEq

def admit (state : AdmissionState) (nullifier successor : Digest)
    (proofValid : Bool) : Option AdmissionState :=
  if proofValid && !state.spent.contains nullifier then
    some { spent := nullifier :: state.spent, permits := successor :: state.permits }
  else none

theorem composedAdmissionIsAtomic (state post : AdmissionState) (nullifier successor : Digest)
    (accepted : admit state nullifier successor true = some post) :
    nullifier ∈ post.spent ∧ successor ∈ post.permits := by
  simp [admit, List.contains_eq_mem] at accepted
  rcases accepted with ⟨_, rfl⟩
  simp

theorem composedAdmissionRejectsReplay (state : AdmissionState) (nullifier successor : Digest)
    (spent : nullifier ∈ state.spent) :
    admit state nullifier successor true = none := by
  simp [admit, List.contains_eq_mem, spent]

end ActiveChain.Billboard
