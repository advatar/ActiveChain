/-!
# ActiveChain testnet faucet transition model

This model fixes the protocol invariants at the boundary between durable faucet
admission and finalized Coin Cell publication. Cryptographic verification and
filesystem atomicity are external assumptions; the state transition itself is
proved testnet/genesis-bound, budget-bounded, reference-idempotent, monotonic,
and receipt-bound.
-/

namespace ActiveChain.Faucet

noncomputable section

local instance (proposition : Prop) : Decidable proposition :=
  Classical.propDecidable proposition

structure Policy where
  chainId : Nat
  genesis : Nat
  faucetAllocation : Nat
  enabled : Bool
  testnet : Bool
  deriving BEq, DecidableEq, Repr

structure Request where
  chainId : Nat
  genesis : Nat
  reference : Nat
  recipient : Nat
  amount : Nat
  deriving BEq, DecidableEq, Repr

structure State where
  issued : Nat
  acceptedReferences : List Nat
  deriving BEq, DecidableEq, Repr

def Admissible (policy : Policy) (state : State) (request : Request) : Prop :=
  policy.enabled = true ∧
    policy.testnet = true ∧
    request.chainId = policy.chainId ∧
    request.genesis = policy.genesis ∧
    request.reference ≠ 0 ∧
    request.recipient ≠ 0 ∧
    0 < request.amount ∧
    request.reference ∉ state.acceptedReferences ∧
    state.issued + request.amount ≤ policy.faucetAllocation

def admit (policy : Policy) (state : State) (request : Request) : Option State :=
  if Admissible policy state request then
    some {
      issued := state.issued + request.amount
      acceptedReferences := request.reference :: state.acceptedReferences
    }
  else
    none

theorem successImpliesAdmissible
    (policy : Policy) (pre post : State) (request : Request)
    (accepted : admit policy pre request = some post) :
    Admissible policy pre request := by
  by_cases valid : Admissible policy pre request
  · exact valid
  · simp [admit, valid] at accepted

theorem successIsTestnetAndGenesisBound
    (policy : Policy) (pre post : State) (request : Request)
    (accepted : admit policy pre request = some post) :
    policy.testnet = true ∧ request.chainId = policy.chainId ∧
      request.genesis = policy.genesis := by
  rcases successImpliesAdmissible policy pre post request accepted with
    ⟨_, testnet, chain, genesis, _⟩
  exact ⟨testnet, chain, genesis⟩

theorem successPreservesAllocationBound
    (policy : Policy) (pre post : State) (request : Request)
    (accepted : admit policy pre request = some post) :
    post.issued ≤ policy.faucetAllocation := by
  have valid := successImpliesAdmissible policy pre post request accepted
  simp [admit, valid] at accepted
  subst post
  exact valid.2.2.2.2.2.2.2.2

theorem successIncreasesIssuedExactly
    (policy : Policy) (pre post : State) (request : Request)
    (accepted : admit policy pre request = some post) :
    post.issued = pre.issued + request.amount := by
  have valid := successImpliesAdmissible policy pre post request accepted
  simp [admit, valid] at accepted
  subst post
  rfl

theorem successRecordsReference
    (policy : Policy) (pre post : State) (request : Request)
    (accepted : admit policy pre request = some post) :
    request.reference ∈ post.acceptedReferences := by
  have valid := successImpliesAdmissible policy pre post request accepted
  simp [admit, valid] at accepted
  subst post
  simp

theorem acceptedReferenceCannotReplay
    (policy : Policy) (pre post : State) (request : Request)
    (accepted : admit policy pre request = some post) :
    admit policy post request = none := by
  have used := successRecordsReference policy pre post request accepted
  have invalid : ¬ Admissible policy post request := by
    intro valid
    rcases valid with ⟨_, _, _, _, _, _, _, fresh, _⟩
    exact fresh used
  simp [admit, invalid]

structure FinalityEvidence where
  chainId : Nat
  genesis : Nat
  reference : Nat
  recipient : Nat
  amount : Nat
  transaction : Nat
  finalizedHeight : Nat
  certificateVerified : Bool
  deriving BEq, DecidableEq, Repr

def ReceiptBound
    (policy : Policy) (request : Request) (evidence : FinalityEvidence) : Prop :=
  evidence.certificateVerified = true ∧
    evidence.chainId = policy.chainId ∧
    evidence.genesis = policy.genesis ∧
    evidence.reference = request.reference ∧
    evidence.recipient = request.recipient ∧
    evidence.amount = request.amount ∧
    evidence.transaction ≠ 0 ∧
    evidence.finalizedHeight ≠ 0

def finalize
    (policy : Policy) (request : Request) (evidence : FinalityEvidence) : Bool :=
  decide (ReceiptBound policy request evidence)

theorem finalizedReceiptHasExactBinding
    (policy : Policy) (request : Request) (evidence : FinalityEvidence)
    (finalized : finalize policy request evidence = true) :
    ReceiptBound policy request evidence := by
  simpa [finalize] using finalized

theorem substitutedReceiptRejected
    (policy : Policy) (request : Request) (evidence : FinalityEvidence)
    (substituted : evidence.reference ≠ request.reference) :
    finalize policy request evidence = false := by
  have invalid : ¬ ReceiptBound policy request evidence := by
    intro bound
    rcases bound with ⟨_, _, _, exactReference, _⟩
    exact substituted exactReference
  simp [finalize, invalid]

end

end ActiveChain.Faucet
