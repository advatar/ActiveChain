/-!
# ActiveChain weighted-consensus safety model

This dependency-free model closes the arithmetic part of the consensus quorum
argument for arbitrary natural-number stake partitions:

* two quorums whose stake is strictly greater than two thirds of total stake
  have intersection stake strictly greater than one third of total stake;
* when Byzantine stake is strictly less than one third, that intersection is
  strictly larger than the entire Byzantine budget; and
* if the aggregate weights refine to concrete signer sets and honest signatures
  refine to one shared durable vote-lock table, two certificates for one slot
  must carry the same digest.

The final refinement from aggregate weights to concrete, distinct validator
identities is intentionally an explicit premise.  ML-DSA authenticity, stake
snapshot construction, integer-overflow rejection, and durable storage are
implementation/refinement obligations rather than Lean axioms.
-/

namespace ActiveChain.WeightedConsensus

abbrev ValidatorId := Nat
abbrev Digest := Nat

/-! ## Aggregate weighted-quorum arithmetic -/

/--
The exhaustive, disjoint Venn partition induced by two signer sets.  Every
field is an arbitrary natural-number stake aggregate.  Constructing these four
aggregates from the Rust validator snapshot is a separate signer-set
refinement obligation.
-/
structure StakePartition where
  leftOnlyStake : Nat
  rightOnlyStake : Nat
  intersectionStake : Nat
  neitherStake : Nat
  deriving BEq, DecidableEq, Repr

def StakePartition.totalStake (partition : StakePartition) : Nat :=
  partition.leftOnlyStake + partition.rightOnlyStake +
    partition.intersectionStake + partition.neitherStake

def StakePartition.leftQuorumStake (partition : StakePartition) : Nat :=
  partition.leftOnlyStake + partition.intersectionStake

def StakePartition.rightQuorumStake (partition : StakePartition) : Nat :=
  partition.rightOnlyStake + partition.intersectionStake

/-- Subtraction- and division-free encoding of `quorum / total > 2 / 3`. -/
def StrictTwoThirds (quorumStake totalStake : Nat) : Prop :=
  totalStake * 2 < quorumStake * 3

/-- Subtraction- and division-free encoding of `Byzantine / total < 1 / 3`. -/
def BelowOneThird (byzantineStake totalStake : Nat) : Prop :=
  byzantineStake * 3 < totalStake

/--
Two strict two-thirds quorums overlap in strictly more than one third of total
stake, for every assignment of natural-number weights to the four partitions.
-/
theorem strictTwoThirdsIntersectionExceedsOneThird
    (partition : StakePartition)
    (leftQuorum :
      StrictTwoThirds partition.leftQuorumStake partition.totalStake)
    (rightQuorum :
      StrictTwoThirds partition.rightQuorumStake partition.totalStake) :
    partition.totalStake < partition.intersectionStake * 3 := by
  unfold StrictTwoThirds at leftQuorum rightQuorum
  unfold StakePartition.leftQuorumStake at leftQuorum
  unfold StakePartition.rightQuorumStake at rightQuorum
  unfold StakePartition.totalStake at leftQuorum rightQuorum ⊢
  omega

/--
Under a strict one-third Byzantine bound, the common stake of two strict
two-thirds quorums exceeds the entire Byzantine stake budget.
-/
theorem strictTwoThirdsIntersectionExceedsByzantineBudget
    (partition : StakePartition) (byzantineStake : Nat)
    (leftQuorum :
      StrictTwoThirds partition.leftQuorumStake partition.totalStake)
    (rightQuorum :
      StrictTwoThirds partition.rightQuorumStake partition.totalStake)
    (byzantineBound : BelowOneThird byzantineStake partition.totalStake) :
    byzantineStake < partition.intersectionStake := by
  have intersectionBound :=
    strictTwoThirdsIntersectionExceedsOneThird partition leftQuorum rightQuorum
  unfold BelowOneThird at byzantineBound
  omega

/-! ## Signer-set and durable vote-lock composition -/

/-- Consensus domain in which one validator may authorize at most one digest. -/
structure Slot where
  chainId : Nat
  epoch : Nat
  validatorSetRoot : Digest
  height : Nat
  round : Nat
  deriving BEq, DecidableEq, Repr

/-- A certificate view parameterized by one exact consensus slot. -/
structure QuorumCertificate (slot : Slot) where
  digest : Digest
  signedBy : ValidatorId → Prop

/--
One durable vote-lock value per validator and fully domain-separated slot.  A
single table is shared by all certificate observations, abstracting atomic
write-before-sign persistence and restoration before signing after restart.
-/
abbrev DurableVoteLocks := ValidatorId → Slot → Option Digest

/-- Every honest signature in a certificate must agree with the durable lock. -/
def CertificateRespectsLocks
    {slot : Slot}
    (locks : DurableVoteLocks)
    (honest : ValidatorId → Prop)
    (certificate : QuorumCertificate slot) : Prop :=
  ∀ validator,
    honest validator →
      certificate.signedBy validator →
        locks validator slot = some certificate.digest

/--
Concrete signer-set refinement required from the aggregate partition: if the
intersection weight exceeds all Byzantine stake, there is an honest validator
whose distinct identity occurs in both certificate signer sets.
-/
def AggregateIntersectionRefinesToSigners
    {slot : Slot}
    (partition : StakePartition)
    (byzantineStake : Nat)
    (honest : ValidatorId → Prop)
    (left right : QuorumCertificate slot) : Prop :=
  byzantineStake < partition.intersectionStake →
    ∃ validator,
      honest validator ∧
        left.signedBy validator ∧
        right.signedBy validator

/-- One common honest signer governed by the shared durable lock forces equality. -/
theorem commonHonestLockedSignerForcesSameDigest
    {slot : Slot}
    (locks : DurableVoteLocks)
    (honest : ValidatorId → Prop)
    (left right : QuorumCertificate slot)
    (leftLocked : CertificateRespectsLocks locks honest left)
    (rightLocked : CertificateRespectsLocks locks honest right)
    (validator : ValidatorId)
    (validatorHonest : honest validator)
    (signedLeft : left.signedBy validator)
    (signedRight : right.signedBy validator) :
    left.digest = right.digest := by
  have leftLock := leftLocked validator validatorHonest signedLeft
  have rightLock := rightLocked validator validatorHonest signedRight
  exact Option.some.inj (leftLock.symm.trans rightLock)

/--
Composed weighted-consensus safety theorem.  Two valid strict weighted QCs for
the same chain/epoch/set/height/round slot cannot certify different digests.
-/
theorem strictWeightedQuorumCertificatesHaveSameDigest
    {slot : Slot}
    (partition : StakePartition)
    (byzantineStake : Nat)
    (locks : DurableVoteLocks)
    (honest : ValidatorId → Prop)
    (left right : QuorumCertificate slot)
    (leftQuorum :
      StrictTwoThirds partition.leftQuorumStake partition.totalStake)
    (rightQuorum :
      StrictTwoThirds partition.rightQuorumStake partition.totalStake)
    (byzantineBound : BelowOneThird byzantineStake partition.totalStake)
    (signerRefinement :
      AggregateIntersectionRefinesToSigners
        partition byzantineStake honest left right)
    (leftLocked : CertificateRespectsLocks locks honest left)
    (rightLocked : CertificateRespectsLocks locks honest right) :
    left.digest = right.digest := by
  have intersectionExceedsByzantine :=
    strictTwoThirdsIntersectionExceedsByzantineBudget
      partition byzantineStake leftQuorum rightQuorum byzantineBound
  obtain ⟨validator, validatorHonest, signedLeft, signedRight⟩ :=
    signerRefinement intersectionExceedsByzantine
  exact commonHonestLockedSignerForcesSameDigest
    locks honest left right leftLocked rightLocked validator validatorHonest
      signedLeft signedRight

/-- Direct contradiction form used by safety reviews and conformance tests. -/
theorem conflictingStrictWeightedQuorumCertificatesImpossible
    {slot : Slot}
    (partition : StakePartition)
    (byzantineStake : Nat)
    (locks : DurableVoteLocks)
    (honest : ValidatorId → Prop)
    (left right : QuorumCertificate slot)
    (leftQuorum :
      StrictTwoThirds partition.leftQuorumStake partition.totalStake)
    (rightQuorum :
      StrictTwoThirds partition.rightQuorumStake partition.totalStake)
    (byzantineBound : BelowOneThird byzantineStake partition.totalStake)
    (signerRefinement :
      AggregateIntersectionRefinesToSigners
        partition byzantineStake honest left right)
    (leftLocked : CertificateRespectsLocks locks honest left)
    (rightLocked : CertificateRespectsLocks locks honest right) :
    ¬ left.digest ≠ right.digest := by
  intro conflict
  exact conflict
    (strictWeightedQuorumCertificatesHaveSameDigest
      partition byzantineStake locks honest left right leftQuorum rightQuorum
        byzantineBound signerRefinement leftLocked rightLocked)

end ActiveChain.WeightedConsensus
