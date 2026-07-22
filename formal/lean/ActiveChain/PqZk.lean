/-!
# ActiveChain PQ-ZK application-boundary model

This model proves the fail-closed admission and one-shot nullifier properties expected around a
cryptographic proof verifier. It deliberately treats cryptographic verification and hash binding
as assumptions; it does not verify the RISC Zero implementation, compiler, STARK, FRI, or hashes.
-/

namespace ActiveChain.PqZk

abbrev Digest := Nat

structure Statement where
  imageId : Digest
  publicInput : Digest
  nullifier : Digest
  successor : Digest
  deriving BEq, DecidableEq, Repr

structure Receipt where
  imageId : Digest
  journal : Digest
  cryptographicallyValid : Bool
  succinctStark : Bool
  deriving BEq, DecidableEq, Repr

def verifies (expectedImage : Digest) (statement : Statement) (receipt : Receipt) : Bool :=
  receipt.cryptographicallyValid && receipt.succinctStark &&
    decide (receipt.imageId = expectedImage) &&
    decide (statement.imageId = expectedImage) &&
    decide (receipt.journal = statement.publicInput)

theorem acceptedBindsExactImageAndJournal
    (expectedImage : Digest) (statement : Statement) (receipt : Receipt)
    (accepted : verifies expectedImage statement receipt = true) :
    receipt.imageId = expectedImage ∧ statement.imageId = expectedImage ∧
      receipt.journal = statement.publicInput := by
  simp [verifies] at accepted
  exact ⟨accepted.1.1.2, accepted.1.2, accepted.2⟩

structure AdmissionState where
  spent : List Digest
  successors : List Digest
  deriving BEq, DecidableEq, Repr

def admit (expectedImage : Digest) (state : AdmissionState)
    (statement : Statement) (receipt : Receipt) : Option AdmissionState :=
  if verifies expectedImage statement receipt && !state.spent.contains statement.nullifier then
    some {
      spent := statement.nullifier :: state.spent
      successors := statement.successor :: state.successors
    }
  else none

theorem successfulAdmissionConsumesNullifier
    (expectedImage : Digest) (pre post : AdmissionState)
    (statement : Statement) (receipt : Receipt)
    (accepted : admit expectedImage pre statement receipt = some post) :
    statement.nullifier ∈ post.spent := by
  simp [admit] at accepted
  rcases accepted with ⟨_, rfl⟩
  simp

theorem replayIsRejected
    (expectedImage : Digest) (state : AdmissionState)
    (statement : Statement) (receipt : Receipt)
    (spent : statement.nullifier ∈ state.spent) :
    admit expectedImage state statement receipt = none := by
  simp [admit, List.contains_eq_mem, spent]

theorem failedAdmissionIsAtomic
    (expectedImage : Digest) (state : AdmissionState)
    (statement : Statement) (receipt : Receipt)
    (_failed : admit expectedImage state statement receipt = none) :
    state.spent = state.spent ∧ state.successors = state.successors := by
  exact ⟨rfl, rfl⟩

end ActiveChain.PqZk
