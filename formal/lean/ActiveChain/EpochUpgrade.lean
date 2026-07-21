/-!
# ActiveChain epoch and protocol-upgrade activation model

This dependency-free model fixes the safety contract for validator-set changes
and protocol upgrades.  An accepted transition advances exactly one height and
either retains the active context or consumes finalized authorization that was
recorded before its exact activation height.  Validator epochs advance by one,
protocol revisions increase strictly, and retired validator-set roots cannot be
reactivated.

The model also defines the context check applied to finalized certificates: a
certificate is accepted only under the currently active epoch, validator-set
root, and protocol revision.
-/

namespace ActiveChain.EpochUpgrade

abbrev Digest := Nat
abbrev Epoch := Nat
abbrev Revision := Nat

/-- Durable control-plane state needed to reject rollback and retired sets. -/
structure ChainState where
  height : Nat
  epoch : Epoch
  validatorSetRoot : Digest
  revision : Revision
  retiredValidatorSetRoots : List Digest
  deriving BEq, DecidableEq, Repr

/-- Candidate context at the next finalized height. -/
structure Candidate where
  height : Nat
  epoch : Epoch
  validatorSetRoot : Digest
  revision : Revision
  deriving BEq, DecidableEq, Repr

/-- Finalized authorization for one consecutive epoch and validator-set change. -/
structure ValidatorSetAuthorization where
  finalized : Bool
  authorizedAtHeight : Nat
  activationHeight : Nat
  fromEpoch : Epoch
  toEpoch : Epoch
  previousRoot : Digest
  nextRoot : Digest
  deriving BEq, DecidableEq, Repr

/-- Finalized authorization for one strictly increasing protocol revision. -/
structure ProtocolUpgradeAuthorization where
  finalized : Bool
  authorizedAtHeight : Nat
  activationHeight : Nat
  previousRevision : Revision
  nextRevision : Revision
  deriving BEq, DecidableEq, Repr

structure ActivationEvidence where
  validatorSet : ValidatorSetAuthorization
  protocolUpgrade : ProtocolUpgradeAuthorization
  deriving BEq, DecidableEq, Repr

/-- A validator context is unchanged, or changes exactly once under prior,
finalized, consecutive-epoch authorization. -/
def ValidatorSetAllowed
    (current : ChainState) (candidate : Candidate)
    (authorization : ValidatorSetAuthorization) : Prop :=
  (candidate.epoch = current.epoch ∧
      candidate.validatorSetRoot = current.validatorSetRoot) ∨
    (authorization.finalized = true ∧
      authorization.authorizedAtHeight ≤ current.height ∧
      authorization.authorizedAtHeight < authorization.activationHeight ∧
      authorization.activationHeight = candidate.height ∧
      authorization.fromEpoch = current.epoch ∧
      authorization.toEpoch = current.epoch + 1 ∧
      candidate.epoch = authorization.toEpoch ∧
      authorization.previousRoot = current.validatorSetRoot ∧
      authorization.nextRoot = candidate.validatorSetRoot ∧
      candidate.validatorSetRoot ≠ current.validatorSetRoot ∧
      candidate.validatorSetRoot ∉ current.retiredValidatorSetRoots)

/-- A protocol revision is unchanged, or changes exactly at the activation
height under prior finalized authorization to a strictly greater revision. -/
def RevisionAllowed
    (current : ChainState) (candidate : Candidate)
    (authorization : ProtocolUpgradeAuthorization) : Prop :=
  candidate.revision = current.revision ∨
    (authorization.finalized = true ∧
      authorization.authorizedAtHeight ≤ current.height ∧
      authorization.authorizedAtHeight < authorization.activationHeight ∧
      authorization.activationHeight = candidate.height ∧
      authorization.previousRevision = current.revision ∧
      authorization.nextRevision = candidate.revision ∧
      current.revision < candidate.revision)

instance validatorSetAllowedDecidable
    (current : ChainState) (candidate : Candidate)
    (authorization : ValidatorSetAuthorization) :
    Decidable (ValidatorSetAllowed current candidate authorization) := by
  unfold ValidatorSetAllowed
  infer_instance

instance revisionAllowedDecidable
    (current : ChainState) (candidate : Candidate)
    (authorization : ProtocolUpgradeAuthorization) :
    Decidable (RevisionAllowed current candidate authorization) := by
  unfold RevisionAllowed
  infer_instance

/-- The modeled state transition advances one finalized height. -/
def TransitionValid
    (current : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence) : Prop :=
  candidate.height = current.height + 1 ∧
    ValidatorSetAllowed current candidate evidence.validatorSet ∧
    RevisionAllowed current candidate evidence.protocolUpgrade

instance transitionValidDecidable
    (current : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence) :
    Decidable (TransitionValid current candidate evidence) := by
  unfold TransitionValid
  infer_instance

def verifyTransition
    (current : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence) : Bool :=
  decide (TransitionValid current candidate evidence)

def Candidate.toState (current : ChainState) (candidate : Candidate) : ChainState :=
  {
    height := candidate.height
    epoch := candidate.epoch
    validatorSetRoot := candidate.validatorSetRoot
    revision := candidate.revision
    retiredValidatorSetRoots :=
      if candidate.validatorSetRoot = current.validatorSetRoot then
        current.retiredValidatorSetRoots
      else
        current.validatorSetRoot :: current.retiredValidatorSetRoots
  }

def advance
    (current : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence) : Option ChainState :=
  if verifyTransition current candidate evidence then
    some (candidate.toState current)
  else
    none

theorem verifyTransition_iff
    (current : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence) :
    verifyTransition current candidate evidence = true ↔
      TransitionValid current candidate evidence := by
  simp [verifyTransition]

theorem successfulAdvanceIsValid
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (accepted : advance current candidate evidence = some post) :
    TransitionValid current candidate evidence := by
  unfold advance at accepted
  split at accepted
  next verified => exact (verifyTransition_iff current candidate evidence).mp verified
  next => simp at accepted

theorem successfulAdvanceReturnsCandidateState
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (accepted : advance current candidate evidence = some post) :
    post = candidate.toState current := by
  unfold advance at accepted
  split at accepted
  next => simp_all
  next => simp at accepted

theorem validatorSetChangeRequiresPriorFinalizedAuthorization
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (changed : candidate.validatorSetRoot ≠ current.validatorSetRoot)
    (accepted : advance current candidate evidence = some post) :
    evidence.validatorSet.finalized = true ∧
      evidence.validatorSet.authorizedAtHeight ≤ current.height ∧
      evidence.validatorSet.authorizedAtHeight < evidence.validatorSet.activationHeight := by
  have valid := successfulAdvanceIsValid current post candidate evidence accepted
  rcases valid.2.1 with unchanged | activated
  · exact False.elim (changed unchanged.2)
  · exact ⟨activated.1, activated.2.1, activated.2.2.1⟩

theorem validatorSetChangeOccursAtExactActivationHeight
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (changed : candidate.validatorSetRoot ≠ current.validatorSetRoot)
    (accepted : advance current candidate evidence = some post) :
    candidate.height = evidence.validatorSet.activationHeight := by
  have valid := successfulAdvanceIsValid current post candidate evidence accepted
  rcases valid.2.1 with unchanged | activated
  · exact False.elim (changed unchanged.2)
  · exact activated.2.2.2.1.symm

theorem validatorSetChangeAdvancesOneEpoch
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (changed : candidate.validatorSetRoot ≠ current.validatorSetRoot)
    (accepted : advance current candidate evidence = some post) :
    post.epoch = current.epoch + 1 := by
  have valid := successfulAdvanceIsValid current post candidate evidence accepted
  have postState := successfulAdvanceReturnsCandidateState current post candidate evidence accepted
  rcases valid.2.1 with unchanged | activated
  · exact False.elim (changed unchanged.2)
  · rw [postState]
    exact activated.2.2.2.2.2.2.1.trans activated.2.2.2.2.2.1

theorem protocolChangeRequiresPriorFinalizedAuthorization
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (changed : candidate.revision ≠ current.revision)
    (accepted : advance current candidate evidence = some post) :
    evidence.protocolUpgrade.finalized = true ∧
      evidence.protocolUpgrade.authorizedAtHeight ≤ current.height ∧
      evidence.protocolUpgrade.authorizedAtHeight <
        evidence.protocolUpgrade.activationHeight := by
  have valid := successfulAdvanceIsValid current post candidate evidence accepted
  rcases valid.2.2 with unchanged | activated
  · exact False.elim (changed unchanged)
  · exact ⟨activated.1, activated.2.1, activated.2.2.1⟩

theorem protocolChangeOccursAtExactActivationHeight
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (changed : candidate.revision ≠ current.revision)
    (accepted : advance current candidate evidence = some post) :
    candidate.height = evidence.protocolUpgrade.activationHeight := by
  have valid := successfulAdvanceIsValid current post candidate evidence accepted
  rcases valid.2.2 with unchanged | activated
  · exact False.elim (changed unchanged)
  · exact activated.2.2.2.1.symm

theorem successfulAdvanceIncreasesHeight
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (accepted : advance current candidate evidence = some post) :
    current.height < post.height := by
  have valid := successfulAdvanceIsValid current post candidate evidence accepted
  have postState := successfulAdvanceReturnsCandidateState current post candidate evidence accepted
  rw [postState]
  simp [Candidate.toState, valid.1]

theorem successfulAdvanceDoesNotDecreaseEpoch
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (accepted : advance current candidate evidence = some post) :
    current.epoch ≤ post.epoch := by
  have valid := successfulAdvanceIsValid current post candidate evidence accepted
  have postState := successfulAdvanceReturnsCandidateState current post candidate evidence accepted
  rw [postState]
  change current.epoch ≤ candidate.epoch
  rcases valid.2.1 with unchanged | activated
  · simp [unchanged.1]
  · rw [show candidate.epoch = current.epoch + 1 from
      activated.2.2.2.2.2.2.1.trans activated.2.2.2.2.2.1]
    simp

theorem successfulAdvanceDoesNotDecreaseRevision
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (accepted : advance current candidate evidence = some post) :
    current.revision ≤ post.revision := by
  have valid := successfulAdvanceIsValid current post candidate evidence accepted
  have postState := successfulAdvanceReturnsCandidateState current post candidate evidence accepted
  rw [postState]
  rcases valid.2.2 with unchanged | activated
  · simp [Candidate.toState, unchanged]
  · exact Nat.le_of_lt activated.2.2.2.2.2.2

theorem protocolChangeStrictlyIncreasesRevision
    (current post : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (changed : candidate.revision ≠ current.revision)
    (accepted : advance current candidate evidence = some post) :
    current.revision < post.revision := by
  have valid := successfulAdvanceIsValid current post candidate evidence accepted
  have postState := successfulAdvanceReturnsCandidateState current post candidate evidence accepted
  rw [postState]
  rcases valid.2.2 with unchanged | activated
  · exact False.elim (changed unchanged)
  · exact activated.2.2.2.2.2.2

theorem epochDowngradeIsRejected
    (current : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (downgrade : candidate.epoch < current.epoch) :
    advance current candidate evidence = none := by
  unfold advance
  cases verified : verifyTransition current candidate evidence with
  | false => simp
  | true =>
      have valid := (verifyTransition_iff current candidate evidence).mp verified
      rcases valid.2.1 with unchanged | activated
      · exact False.elim (Nat.ne_of_lt downgrade unchanged.1)
      · have nextEpoch : candidate.epoch = current.epoch + 1 :=
          activated.2.2.2.2.2.2.1.trans activated.2.2.2.2.2.1
        have monotonic : current.epoch ≤ candidate.epoch := by
          rw [nextEpoch]
          exact Nat.le_succ current.epoch
        exact False.elim (Nat.not_lt_of_ge monotonic downgrade)

theorem revisionDowngradeIsRejected
    (current : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (downgrade : candidate.revision < current.revision) :
    advance current candidate evidence = none := by
  unfold advance
  cases verified : verifyTransition current candidate evidence with
  | false => simp
  | true =>
      have valid := (verifyTransition_iff current candidate evidence).mp verified
      rcases valid.2.2 with unchanged | activated
      · exact False.elim (Nat.ne_of_lt downgrade unchanged)
      · exact False.elim (Nat.not_lt_of_ge
          (Nat.le_of_lt activated.2.2.2.2.2.2) downgrade)

theorem missedValidatorActivationHeightIsRejected
    (current : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (changed : candidate.validatorSetRoot ≠ current.validatorSetRoot)
    (missed : candidate.height ≠ evidence.validatorSet.activationHeight) :
    advance current candidate evidence = none := by
  unfold advance
  cases verified : verifyTransition current candidate evidence with
  | false => simp
  | true =>
      have valid := (verifyTransition_iff current candidate evidence).mp verified
      rcases valid.2.1 with unchanged | activated
      · exact False.elim (changed unchanged.2)
      · exact False.elim (missed activated.2.2.2.1.symm)

theorem missedProtocolActivationHeightIsRejected
    (current : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (changed : candidate.revision ≠ current.revision)
    (missed : candidate.height ≠ evidence.protocolUpgrade.activationHeight) :
    advance current candidate evidence = none := by
  unfold advance
  cases verified : verifyTransition current candidate evidence with
  | false => simp
  | true =>
      have valid := (verifyTransition_iff current candidate evidence).mp verified
      rcases valid.2.2 with unchanged | activated
      · exact False.elim (changed unchanged)
      · exact False.elim (missed activated.2.2.2.1.symm)

theorem retiredValidatorSetCannotReactivate
    (current : ChainState) (candidate : Candidate)
    (evidence : ActivationEvidence)
    (retired : candidate.validatorSetRoot ∈ current.retiredValidatorSetRoots)
    (changed : candidate.validatorSetRoot ≠ current.validatorSetRoot) :
    advance current candidate evidence = none := by
  unfold advance
  cases verified : verifyTransition current candidate evidence with
  | false => simp
  | true =>
      have valid := (verifyTransition_iff current candidate evidence).mp verified
      rcases valid.2.1 with unchanged | activated
      · exact False.elim (changed unchanged.2)
      · exact False.elim (activated.2.2.2.2.2.2.2.2.2.2 retired)

/-! ## Active certificate-context rejection -/

structure CertificateContext where
  epoch : Epoch
  validatorSetRoot : Digest
  revision : Revision
  deriving BEq, DecidableEq, Repr

def verifyCertificateContext
    (current : ChainState) (certificate : CertificateContext) : Bool :=
  decide (certificate.epoch = current.epoch) &&
    decide (certificate.validatorSetRoot = current.validatorSetRoot) &&
    decide (certificate.revision = current.revision)

theorem certificateContextAccepted_iff
    (current : ChainState) (certificate : CertificateContext) :
    verifyCertificateContext current certificate = true ↔
      certificate.epoch = current.epoch ∧
        certificate.validatorSetRoot = current.validatorSetRoot ∧
        certificate.revision = current.revision := by
  simp [verifyCertificateContext, and_assoc]

theorem staleEpochCertificateIsRejected
    (current : ChainState) (certificate : CertificateContext)
    (stale : certificate.epoch < current.epoch) :
    verifyCertificateContext current certificate = false := by
  simp [verifyCertificateContext, Nat.ne_of_lt stale]

theorem staleValidatorSetCertificateIsRejected
    (current : ChainState) (certificate : CertificateContext)
    (stale : certificate.validatorSetRoot ≠ current.validatorSetRoot) :
    verifyCertificateContext current certificate = false := by
  simp [verifyCertificateContext, stale]

theorem downgradedRevisionCertificateIsRejected
    (current : ChainState) (certificate : CertificateContext)
    (downgrade : certificate.revision < current.revision) :
    verifyCertificateContext current certificate = false := by
  simp [verifyCertificateContext, Nat.ne_of_lt downgrade]

end ActiveChain.EpochUpgrade
