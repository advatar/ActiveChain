/-!
# Joined authorization-chain model

This model captures the fail-closed conjunction implemented by
`activechain-authorization-kernel`: authenticated finalized evidence is joined before APL,
budgets and invocation replay are checked before execution, and the state plus consumption record
are published as one transition.
-/
namespace ActiveChain.AuthorizationChain

structure Evidence where
  actorSignature : Bool
  finalizedContext : Bool
  credentialSignatures : Bool
  credentialFreshAndActive : Bool
  capabilitySignatures : Bool
  capabilityChainAttenuated : Bool
  capabilityActive : Bool
  holderAndScopeBound : Bool
  requestDerivedExactly : Bool
  aplPermit : Bool
  obligationsSupported : Bool
  transitionBound : Bool
  deriving BEq, DecidableEq

def Evidence.Valid (e : Evidence) : Prop :=
  e.actorSignature = true ∧ e.finalizedContext = true ∧
  e.credentialSignatures = true ∧ e.credentialFreshAndActive = true ∧
  e.capabilitySignatures = true ∧ e.capabilityChainAttenuated = true ∧
  e.capabilityActive = true ∧ e.holderAndScopeBound = true ∧
  e.requestDerivedExactly = true ∧ e.aplPermit = true ∧
  e.obligationsSupported = true ∧ e.transitionBound = true

instance (e : Evidence) : Decidable e.Valid := by
  unfold Evidence.Valid
  infer_instance

structure Budget where
  uses : Nat
  money : Nat
  compute : Nat
  maxUses : Nat
  maxMoney : Nat
  maxCompute : Nat
  deriving BEq, DecidableEq

def Budget.canConsume (b : Budget) (money compute : Nat) : Prop :=
  b.uses + 1 ≤ b.maxUses ∧ b.money + money ≤ b.maxMoney ∧
  b.compute + compute ≤ b.maxCompute

instance (b : Budget) (money compute : Nat) : Decidable (b.canConsume money compute) := by
  unfold Budget.canConsume
  infer_instance

def Budget.consume (b : Budget) (money compute : Nat) : Budget :=
  { b with uses := b.uses + 1, money := b.money + money,
           compute := b.compute + compute }

structure Runtime where
  consumed : List Nat
  budget : Budget
  objectState : Nat
  deriving BEq, DecidableEq

structure Candidate where
  invocation : Nat
  evidence : Evidence
  money : Nat
  compute : Nat
  postState : Nat
  deriving BEq, DecidableEq

def admit (state : Runtime) (candidate : Candidate) : Option Runtime :=
  if candidate.evidence.Valid ∧ candidate.invocation ∉ state.consumed ∧
      state.budget.canConsume candidate.money candidate.compute then
    some { consumed := candidate.invocation :: state.consumed
           budget := state.budget.consume candidate.money candidate.compute
           objectState := candidate.postState }
  else none

theorem admitted_implies_complete_evidence
    (state : Runtime) (candidate : Candidate) (next : Runtime)
    (accepted : admit state candidate = some next) : candidate.evidence.Valid := by
  unfold admit at accepted
  split at accepted
  next valid => exact valid.1
  next => contradiction

theorem admitted_consumes_invocation_and_budgets_atomically
    (state : Runtime) (candidate : Candidate) (next : Runtime)
    (accepted : admit state candidate = some next) :
    next.consumed = candidate.invocation :: state.consumed ∧
    next.budget = state.budget.consume candidate.money candidate.compute ∧
    next.objectState = candidate.postState := by
  unfold admit at accepted
  split at accepted
  next => cases accepted; simp
  next => contradiction

theorem replay_rejected_after_success
    (state : Runtime) (candidate : Candidate) (next : Runtime)
    (accepted : admit state candidate = some next) : admit next candidate = none := by
  have fields := admitted_consumes_invocation_and_budgets_atomically state candidate next accepted
  simp [admit, fields.1]

theorem concurrent_duplicate_has_at_most_one_serial_success
    (state : Runtime) (candidate : Candidate) (first second : Runtime)
    (accepted : admit state candidate = some first) :
    admit first candidate ≠ some second := by
  rw [replay_rejected_after_success state candidate first accepted]
  simp

end ActiveChain.AuthorizationChain
