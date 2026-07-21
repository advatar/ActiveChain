/-!
# ActiveChain native-cash supply model

This dependency-free model fixes the algebraic obligations of the native cash
kernel described by `CASH.md`, `MINT.md`, and `REWARDS.md`:

* a transfer redistributes all consumed value between recipient, change, and
  the security fee reserve;
* issuance succeeds only for a policy-, sequence-, and formula-authorized
  transition whose amount is bounded by its constitutional cap;
* a burn reduces total supply and increases cumulative burn by the same amount;
* redeeming an already-issued reward changes representation, not supply, and a
  reward identifier can be redeemed at most once.

Amounts are modeled by unbounded natural numbers. The Rust refinement must
additionally preserve these equations while rejecting every `u128` overflow.
Policy-hash matching, epoch sequencing, and economics-formula validation are
abstract Boolean observations here; their concrete computation and the
cryptographic binding of reward identifiers remain separate refinement
obligations.
-/

namespace ActiveChain.Cash

/-! ## Supply equation -/

/-- The accounting fields that determine native total supply. -/
structure SupplyState where
  genesisSupply : Nat
  cumulativeIssuance : Nat
  cumulativeBurn : Nat
  totalSupply : Nat
  deriving BEq, DecidableEq, Repr

/-- Subtraction-free form of `total = genesis + issuance - burn`. -/
def SupplyInvariant (state : SupplyState) : Prop :=
  state.totalSupply + state.cumulativeBurn =
    state.genesisSupply + state.cumulativeIssuance

/-- The one-time genesis transition introduces no security issuance or burn. -/
def genesis (amount : Nat) : SupplyState :=
  {
    genesisSupply := amount
    cumulativeIssuance := 0
    cumulativeBurn := 0
    totalSupply := amount
  }

@[simp] theorem genesisSatisfiesSupplyInvariant (amount : Nat) :
    SupplyInvariant (genesis amount) := by
  simp [SupplyInvariant, genesis]

/-! ## Fixed-semantics transfer -/

/-- Public values needed for the native transfer conservation equation. -/
structure TransferIntent where
  inputValue : Nat
  amount : Nat
  fee : Nat
  deriving BEq, DecidableEq, Repr

/-- The fixed cash kernel accepts only funded, non-zero transfers. -/
def TransferIntent.Valid (intent : TransferIntent) : Prop :=
  0 < intent.amount ∧ intent.amount + intent.fee ≤ intent.inputValue

/-- Values created or credited after consuming all transfer inputs. -/
structure TransferResult where
  recipientValue : Nat
  changeValue : Nat
  feeReserveValue : Nat
  deriving BEq, DecidableEq, Repr

/-- Fixed output formation used after validation. -/
def applyTransfer (intent : TransferIntent) : TransferResult :=
  {
    recipientValue := intent.amount
    changeValue := intent.inputValue - (intent.amount + intent.fee)
    feeReserveValue := intent.fee
  }

/-- Every accepted transfer accounts for every consumed native unit exactly. -/
theorem transferValueConservation
    (intent : TransferIntent) (valid : intent.Valid) :
    let result := applyTransfer intent
    result.recipientValue + result.changeValue + result.feeReserveValue =
      intent.inputValue := by
  simp only [TransferIntent.Valid] at valid
  simp only [applyTransfer]
  omega

/-- A transfer does not create or destroy native supply. -/
@[simp] theorem transferPreservesSupply
    (supply : SupplyState) (intent : TransferIntent) :
    (supply, applyTransfer intent).1 = supply := rfl

/-! ## Bounded protocol issuance -/

/-- Abstract observations made by `EpochEconomicsTransition` validation. -/
structure IssuanceTransition where
  amount : Nat
  issuanceCap : Nat
  policyMatches : Bool
  sequenceMatches : Bool
  formulaMatches : Bool
  deriving BEq, DecidableEq, Repr

/-- Executable conjunction of all issuance authorization observations. -/
def IssuanceTransition.authorized (transition : IssuanceTransition) : Bool :=
  transition.policyMatches && transition.sequenceMatches &&
    transition.formulaMatches && decide (transition.amount ≤ transition.issuanceCap)

/-- There is no discretionary authority: all three protocol checks and the cap
must hold before issuance can be accepted. -/
def IssuanceTransition.Authorized (transition : IssuanceTransition) : Prop :=
  transition.authorized = true

/-- Apply one authorized epoch issuance. -/
def applyIssuance
    (state : SupplyState) (transition : IssuanceTransition) : Option SupplyState :=
  if transition.authorized then
    some {
      genesisSupply := state.genesisSupply
      cumulativeIssuance := state.cumulativeIssuance + transition.amount
      cumulativeBurn := state.cumulativeBurn
      totalSupply := state.totalSupply + transition.amount
    }
  else
    none

/-- Successful issuance is possible only through the complete authorization
predicate. -/
theorem issuanceSuccessImpliesAuthorization
    (pre post : SupplyState) (transition : IssuanceTransition)
    (accepted : applyIssuance pre transition = some post) :
    transition.Authorized := by
  cases authorization : transition.authorized with
  | false => simp [applyIssuance, authorization] at accepted
  | true => simpa [IssuanceTransition.Authorized] using authorization

/-- In particular, every successful issuance is bounded by its declared cap. -/
theorem authorizedIssuanceIsCapped
    (pre post : SupplyState) (transition : IssuanceTransition)
    (accepted : applyIssuance pre transition = some post) :
    transition.amount ≤ transition.issuanceCap := by
  have authorized := issuanceSuccessImpliesAuthorization pre post transition accepted
  simp [IssuanceTransition.Authorized, IssuanceTransition.authorized] at authorized
  exact authorized.2

@[simp] theorem unauthorizedIssuanceIsRejected
    (state : SupplyState) (transition : IssuanceTransition)
    (unauthorized : ¬ transition.Authorized) :
    applyIssuance state transition = none := by
  unfold IssuanceTransition.Authorized at unauthorized
  cases authorization : transition.authorized with
  | false => simp [applyIssuance, authorization]
  | true => exact False.elim (unauthorized authorization)

/-- An accepted issuance increases both the cumulative-issued counter and total
supply by exactly the authorized amount. -/
theorem issuanceChangesSupplyExactly
    (pre post : SupplyState) (transition : IssuanceTransition)
    (accepted : applyIssuance pre transition = some post) :
    post.totalSupply = pre.totalSupply + transition.amount ∧
      post.cumulativeIssuance =
        pre.cumulativeIssuance + transition.amount := by
  cases authorization : transition.authorized with
  | false => simp [applyIssuance, authorization] at accepted
  | true =>
    simp [applyIssuance, authorization] at accepted
    subst post
    exact ⟨rfl, rfl⟩

/-- Authorized issuance preserves the native supply equation. -/
theorem issuancePreservesSupplyInvariant
    (pre post : SupplyState) (transition : IssuanceTransition)
    (invariant : SupplyInvariant pre)
    (accepted : applyIssuance pre transition = some post) :
    SupplyInvariant post := by
  cases authorization : transition.authorized with
  | false => simp [applyIssuance, authorization] at accepted
  | true =>
    simp [applyIssuance, authorization] at accepted
    subst post
    unfold SupplyInvariant at invariant ⊢
    change
      (pre.totalSupply + transition.amount) + pre.cumulativeBurn =
        pre.genesisSupply + (pre.cumulativeIssuance + transition.amount)
    omega

/-! ## Permanent burn -/

/-- Burn only value that exists in the pre-state. -/
def applyBurn (state : SupplyState) (amount : Nat) : Option SupplyState :=
  if amount ≤ state.totalSupply then
    some {
      genesisSupply := state.genesisSupply
      cumulativeIssuance := state.cumulativeIssuance
      cumulativeBurn := state.cumulativeBurn + amount
      totalSupply := state.totalSupply - amount
    }
  else
    none

/-- A successful burn reduces total supply by exactly the burned amount. -/
theorem burnReducesSupplyExactly
    (pre post : SupplyState) (amount : Nat)
    (accepted : applyBurn pre amount = some post) :
    post.totalSupply + amount = pre.totalSupply ∧
      post.cumulativeBurn = pre.cumulativeBurn + amount := by
  by_cases bounded : amount ≤ pre.totalSupply
  · simp [applyBurn, bounded] at accepted
    subst post
    constructor
    · change (pre.totalSupply - amount) + amount = pre.totalSupply
      exact Nat.sub_add_cancel bounded
    · rfl
  · simp [applyBurn, bounded] at accepted

/-- Burning preserves the supply equation while decreasing live supply. -/
theorem burnPreservesSupplyInvariant
    (pre post : SupplyState) (amount : Nat)
    (invariant : SupplyInvariant pre)
    (accepted : applyBurn pre amount = some post) :
    SupplyInvariant post := by
  by_cases bounded : amount ≤ pre.totalSupply
  · simp [applyBurn, bounded] at accepted
    subst post
    unfold SupplyInvariant at invariant ⊢
    change
      (pre.totalSupply - amount) + (pre.cumulativeBurn + amount) =
        pre.genesisSupply + pre.cumulativeIssuance
    omega
  · simp [applyBurn, bounded] at accepted

/-! ## Reward redemption is representation-only -/

/-- A reward credit is already supply-bearing when epoch settlement finalizes. -/
structure RewardCredit where
  id : Nat
  amount : Nat
  deriving BEq, DecidableEq, Repr

/-- `outstandingRewards` and `spendableCells` are two representations of value
already included in `supply`. `redeemedRewardIds` is the replay barrier. -/
structure RewardState where
  supply : SupplyState
  outstandingRewards : Nat
  spendableCells : Nat
  redeemedRewardIds : List Nat
  deriving BEq, DecidableEq, Repr

def RewardInvariant (state : RewardState) : Prop :=
  state.outstandingRewards + state.spendableCells = state.supply.totalSupply

/-- Redeem an existing credit without invoking either issuance path. -/
def redeemReward (state : RewardState) (credit : RewardCredit) : Option RewardState :=
  if credit.id ∈ state.redeemedRewardIds then
    none
  else if credit.amount ≤ state.outstandingRewards then
    some {
      supply := state.supply
      outstandingRewards := state.outstandingRewards - credit.amount
      spendableCells := state.spendableCells + credit.amount
      redeemedRewardIds := credit.id :: state.redeemedRewardIds
    }
  else
    none

/-- Redemption moves issued value between representations and cannot mint. -/
theorem rewardRedemptionPreservesSupply
    (pre post : RewardState) (credit : RewardCredit)
    (accepted : redeemReward pre credit = some post) :
    post.supply = pre.supply := by
  by_cases redeemed : credit.id ∈ pre.redeemedRewardIds
  · simp [redeemReward, redeemed] at accepted
  · by_cases funded : credit.amount ≤ pre.outstandingRewards
    · simp [redeemReward, redeemed, funded] at accepted
      subst post
      rfl
    · simp [redeemReward, redeemed, funded] at accepted

/-- Redemption preserves the partition of already-issued supply. -/
theorem rewardRedemptionPreservesAccounting
    (pre post : RewardState) (credit : RewardCredit)
    (invariant : RewardInvariant pre)
    (accepted : redeemReward pre credit = some post) :
    RewardInvariant post := by
  by_cases redeemed : credit.id ∈ pre.redeemedRewardIds
  · simp [redeemReward, redeemed] at accepted
  · by_cases funded : credit.amount ≤ pre.outstandingRewards
    · simp [redeemReward, redeemed, funded] at accepted
      subst post
      simp only [RewardInvariant] at invariant ⊢
      omega
    · simp [redeemReward, redeemed, funded] at accepted

/-- Once a reward identifier succeeds, the replay barrier rejects it forever. -/
theorem rewardRedemptionIsOneShot
    (pre post : RewardState) (credit : RewardCredit)
    (accepted : redeemReward pre credit = some post) :
    redeemReward post credit = none := by
  by_cases redeemed : credit.id ∈ pre.redeemedRewardIds
  · simp [redeemReward, redeemed] at accepted
  · by_cases funded : credit.amount ≤ pre.outstandingRewards
    · simp [redeemReward, redeemed, funded] at accepted
      subst post
      simp [redeemReward]
    · simp [redeemReward, redeemed, funded] at accepted

/-- Combined no-double-mint statement for reward redemption. -/
theorem rewardRedemptionCannotDoubleMint
    (pre post : RewardState) (credit : RewardCredit)
    (accepted : redeemReward pre credit = some post) :
    post.supply.totalSupply = pre.supply.totalSupply ∧
      redeemReward post credit = none := by
  constructor
  · rw [rewardRedemptionPreservesSupply pre post credit accepted]
  · exact rewardRedemptionIsOneShot pre post credit accepted

end ActiveChain.Cash
