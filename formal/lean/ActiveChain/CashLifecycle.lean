/-!
# ActiveChain native cash lifecycle refinement model

This executable model covers the supply and replay projection shared by authorized issuance,
reward redemption, shielding, unshielding, and durable restart. Cryptographic authorization,
Coin Cell selection, and accumulator correctness are explicit production-boundary assumptions.
-/

namespace ActiveChain.CashLifecycle

structure State where
  supply : Nat
  shieldedPool : Nat
  redeemedRewards : List Nat
  spentNullifiers : List Nat
  deriving BEq, DecidableEq, Inhabited, Repr

def issue (state : State) (amount : Nat) : Option State :=
  if 0 < amount then some { state with supply := state.supply + amount } else none

def redeemReward (state : State) (rewardId : Nat) : Option State :=
  if rewardId ∉ state.redeemedRewards then
    some { state with redeemedRewards := rewardId :: state.redeemedRewards }
  else
    none

def shield (state : State) (amount : Nat) : Option State :=
  if 0 < amount then some { state with shieldedPool := state.shieldedPool + amount } else none

def unshield (state : State) (amount fee nullifier : Nat) : Option State :=
  if 0 < amount ∧ amount + fee ≤ state.shieldedPool ∧ nullifier ∉ state.spentNullifiers then
    some {
      state with
      shieldedPool := state.shieldedPool - (amount + fee)
      spentNullifiers := nullifier :: state.spentNullifiers
    }
  else
    none

def restart (state : State) : State := state

theorem rewardPreservesSupply
    (pre post : State) (rewardId : Nat)
    (accepted : redeemReward pre rewardId = some post) :
    post.supply = pre.supply := by
  simp only [redeemReward] at accepted
  split at accepted
  · exact (Option.some.inj accepted ▸ rfl)
  · contradiction

theorem rewardIsOneShot
    (pre post : State) (rewardId : Nat)
    (accepted : redeemReward pre rewardId = some post) :
    redeemReward post rewardId = none := by
  simp only [redeemReward] at accepted
  split at accepted
  case isTrue =>
    have postEq := Option.some.inj accepted
    rw [← postEq]
    simp [redeemReward]
  case isFalse => contradiction

theorem shieldPreservesSupply
    (pre post : State) (amount : Nat)
    (accepted : shield pre amount = some post) :
    post.supply = pre.supply := by
  simp only [shield] at accepted
  split at accepted
  · exact (congrArg State.supply (Option.some.inj accepted)).symm
  · contradiction

theorem unshieldPreservesSupply
    (pre post : State) (amount fee nullifier : Nat)
    (accepted : unshield pre amount fee nullifier = some post) :
    post.supply = pre.supply := by
  simp only [unshield] at accepted
  split at accepted
  · exact (congrArg State.supply (Option.some.inj accepted)).symm
  · contradiction

theorem unshieldNullifierIsOneShot
    (pre post : State) (amount fee nullifier : Nat)
    (accepted : unshield pre amount fee nullifier = some post) :
    unshield post amount fee nullifier = none := by
  simp only [unshield] at accepted
  split at accepted
  case isTrue =>
    have postEq := Option.some.inj accepted
    rw [← postEq]
    simp [unshield]
  case isFalse => contradiction

theorem restartPreservesState (state : State) : restart state = state := by
  rfl

end ActiveChain.CashLifecycle
