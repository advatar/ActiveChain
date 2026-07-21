/-!
# ActiveChain data-availability and light-client trust model

This dependency-free model fixes the safety boundary described by the
`activechain-data-availability` crate and P-110:

* every restored shard is checked against its indexed commitment;
* reconstruction is accepted only within the declared erasure budget;
* the reconstructed payload is bound to the checkpoint commitment;
* sampling evidence is non-empty, unique, and in range; and
* a light client advances only after checking finality, validator-set,
  checkpoint, state-proof, data-availability, and upgrade evidence.

SHAKE256 collision resistance and Reed--Solomon decoder correctness are
cryptographic/library refinement assumptions.  They are deliberately not
introduced as Lean axioms here.
-/

namespace ActiveChain.DA

abbrev Digest := Nat
abbrev Revision := Nat

/-! ## Indexed shard commitments -/

/-- Structural layout bounds mirrored from the Rust DA kernel. -/
structure Layout where
  dataShards : Nat
  parityShards : Nat
  shardBytes : Nat
  deriving BEq, DecidableEq, Repr

def Layout.totalShards (layout : Layout) : Nat :=
  layout.dataShards + layout.parityShards

def Layout.Valid (layout : Layout) : Prop :=
  0 < layout.dataShards ∧
    0 < layout.parityShards ∧
    layout.totalShards ≤ 256 ∧
    0 < layout.shardBytes ∧
    layout.shardBytes ≤ 1048576

instance layoutValidDecidable (layout : Layout) : Decidable layout.Valid := by
  unfold Layout.Valid Layout.totalShards
  infer_instance

/-- Exact recursive relation between shard position, bytes, and commitment. -/
def CommitmentsMatch
    (hashShard : Nat → List Nat → Digest) :
    Nat → List (List Nat) → List Digest → Prop
  | _, [], [] => True
  | index, shard :: shards, commitment :: commitments =>
      hashShard index shard = commitment ∧
        CommitmentsMatch hashShard (index + 1) shards commitments
  | _, _, _ => False

/-- Executable counterpart of `CommitmentsMatch`.  Unequal list lengths fail. -/
def verifyCommitments
    (hashShard : Nat → List Nat → Digest) :
    Nat → List (List Nat) → List Digest → Bool
  | _, [], [] => true
  | index, shard :: shards, commitment :: commitments =>
      decide (hashShard index shard = commitment) &&
        verifyCommitments hashShard (index + 1) shards commitments
  | _, _, _ => false

theorem verifyCommitments_iff
    (hashShard : Nat → List Nat → Digest)
    (index : Nat) (shards : List (List Nat)) (commitments : List Digest) :
    verifyCommitments hashShard index shards commitments = true ↔
      CommitmentsMatch hashShard index shards commitments := by
  induction shards generalizing index commitments with
  | nil =>
      cases commitments <;> simp [verifyCommitments, CommitmentsMatch]
  | cons shard shards inductionHypothesis =>
      cases commitments with
      | nil => simp [verifyCommitments, CommitmentsMatch]
      | cons commitment commitments =>
          simp [verifyCommitments, CommitmentsMatch, inductionHypothesis]

theorem commitmentsMatchHasExactArity
    (hashShard : Nat → List Nat → Digest)
    (index : Nat) (shards : List (List Nat)) (commitments : List Digest)
    (matchProof : CommitmentsMatch hashShard index shards commitments) :
    shards.length = commitments.length := by
  induction shards generalizing index commitments with
  | nil =>
      cases commitments <;> simp_all [CommitmentsMatch]
  | cons shard shards inductionHypothesis =>
      cases commitments with
      | nil => simp [CommitmentsMatch] at matchProof
      | cons commitment commitments =>
          simp only [CommitmentsMatch] at matchProof
          simp [inductionHypothesis (index + 1) commitments matchProof.2]

theorem acceptedCommitmentsHaveExactArity
    (hashShard : Nat → List Nat → Digest)
    (index : Nat) (shards : List (List Nat)) (commitments : List Digest)
    (accepted : verifyCommitments hashShard index shards commitments = true) :
    shards.length = commitments.length := by
  exact commitmentsMatchHasExactArity hashShard index shards commitments
    ((verifyCommitments_iff hashShard index shards commitments).mp accepted)

theorem mismatchedFirstCommitmentIsRejected
    (hashShard : Nat → List Nat → Digest)
    (index : Nat) (shard : List Nat) (shards : List (List Nat))
    (wrong : Digest) (commitments : List Digest)
    (mismatch : hashShard index shard ≠ wrong) :
    verifyCommitments hashShard index (shard :: shards) (wrong :: commitments) = false := by
  simp [verifyCommitments, mismatch]

/-! ## Sampling and reconstruction acceptance -/

def SamplesValid
    (totalShards requested : Nat) (indices : List Nat) : Prop :=
  0 < requested ∧
    requested ≤ totalShards ∧
    indices.length = requested ∧
    indices.Nodup ∧
    ∀ index ∈ indices, index < totalShards

def verifySamples (totalShards requested : Nat) (indices : List Nat) : Bool :=
  decide (0 < requested) &&
    decide (requested ≤ totalShards) &&
    decide (indices.length = requested) &&
    decide indices.Nodup &&
    indices.all (fun index => decide (index < totalShards))

theorem verifySamples_iff (totalShards requested : Nat) (indices : List Nat) :
    verifySamples totalShards requested indices = true ↔
      SamplesValid totalShards requested indices := by
  simp [verifySamples, SamplesValid, List.all_eq_true, and_assoc]

@[simp] theorem emptySampleIsRejected (totalShards : Nat) :
    verifySamples totalShards 0 [] = false := by
  simp [verifySamples]

theorem acceptedSampleHasRequestedCardinality
    (totalShards requested : Nat) (indices : List Nat)
    (accepted : verifySamples totalShards requested indices = true) :
    indices.length = requested := by
  exact ((verifySamples_iff totalShards requested indices).mp accepted).2.2.1

/-- Canonical payload extraction from reconstructed data shards. -/
def restoredPayload
    (layout : Layout) (payloadLength : Nat)
    (restoredShards : List (List Nat)) : List Nat :=
  (restoredShards.take layout.dataShards).flatten.take payloadLength

structure ReconstructionEvidence where
  layout : Layout
  payloadLength : Nat
  missing : List Nat
  restoredShards : List (List Nat)
  commitments : List Digest
  expectedPayloadCommitment : Digest
  deriving Repr

def ReconstructionEvidence.Valid
    (hashShard : Nat → List Nat → Digest)
    (hashPayload : List Nat → Digest)
    (evidence : ReconstructionEvidence) : Prop :=
  evidence.layout.Valid ∧
    0 < evidence.payloadLength ∧
    evidence.payloadLength ≤ evidence.layout.dataShards * evidence.layout.shardBytes ∧
    evidence.missing.Nodup ∧
    evidence.missing.length ≤ evidence.layout.parityShards ∧
    (∀ index ∈ evidence.missing, index < evidence.layout.totalShards) ∧
    evidence.restoredShards.length = evidence.layout.totalShards ∧
    (∀ shard ∈ evidence.restoredShards, shard.length = evidence.layout.shardBytes) ∧
    CommitmentsMatch hashShard 0 evidence.restoredShards evidence.commitments ∧
    hashPayload
          (restoredPayload evidence.layout evidence.payloadLength evidence.restoredShards) =
        evidence.expectedPayloadCommitment

def verifyReconstruction
    (hashShard : Nat → List Nat → Digest)
    (hashPayload : List Nat → Digest)
    (evidence : ReconstructionEvidence) : Bool :=
  decide evidence.layout.Valid &&
    decide (0 < evidence.payloadLength) &&
    decide
      (evidence.payloadLength ≤ evidence.layout.dataShards * evidence.layout.shardBytes) &&
    decide evidence.missing.Nodup &&
    decide (evidence.missing.length ≤ evidence.layout.parityShards) &&
    evidence.missing.all
      (fun index => decide (index < evidence.layout.totalShards)) &&
    decide (evidence.restoredShards.length = evidence.layout.totalShards) &&
    evidence.restoredShards.all
      (fun shard => decide (shard.length = evidence.layout.shardBytes)) &&
    verifyCommitments hashShard 0 evidence.restoredShards evidence.commitments &&
    decide
      (hashPayload
          (restoredPayload evidence.layout evidence.payloadLength evidence.restoredShards) =
        evidence.expectedPayloadCommitment)

theorem verifyReconstruction_iff
    (hashShard : Nat → List Nat → Digest)
    (hashPayload : List Nat → Digest)
    (evidence : ReconstructionEvidence) :
    verifyReconstruction hashShard hashPayload evidence = true ↔
      evidence.Valid hashShard hashPayload := by
  simp [verifyReconstruction, ReconstructionEvidence.Valid,
    verifyCommitments_iff, List.all_eq_true, and_assoc]

theorem acceptedReconstructionIsWithinErasureBudget
    (hashShard : Nat → List Nat → Digest)
    (hashPayload : List Nat → Digest)
    (evidence : ReconstructionEvidence)
    (accepted : verifyReconstruction hashShard hashPayload evidence = true) :
    evidence.missing.length ≤ evidence.layout.parityShards := by
  rcases (verifyReconstruction_iff hashShard hashPayload evidence).mp accepted with
    ⟨_, _, _, _, erasureBound, _⟩
  exact erasureBound

theorem acceptedReconstructionBindsPayloadCommitment
    (hashShard : Nat → List Nat → Digest)
    (hashPayload : List Nat → Digest)
    (evidence : ReconstructionEvidence)
    (accepted : verifyReconstruction hashShard hashPayload evidence = true) :
    hashPayload
        (restoredPayload evidence.layout evidence.payloadLength evidence.restoredShards) =
      evidence.expectedPayloadCommitment := by
  rcases (verifyReconstruction_iff hashShard hashPayload evidence).mp accepted with
    ⟨_, _, _, _, _, _, _, _, _, payloadBound⟩
  exact payloadBound

/-! ## Fail-closed light-client trust transition -/

structure TrustedHead where
  height : Nat
  stateRoot : Digest
  validatorSetRoot : Digest
  revision : Revision
  deriving BEq, DecidableEq, Repr

structure Candidate where
  height : Nat
  stateRoot : Digest
  validatorSetRoot : Digest
  revision : Revision
  payloadCommitment : Digest
  deriving BEq, DecidableEq, Repr

structure QuorumCertificate where
  valid : Bool
  height : Nat
  stateRoot : Digest
  validatorSetRoot : Digest
  revision : Revision
  deriving BEq, DecidableEq, Repr

structure Checkpoint where
  height : Nat
  stateRoot : Digest
  validatorSetRoot : Digest
  revision : Revision
  payloadCommitment : Digest
  deriving BEq, DecidableEq, Repr

structure ValidatorSetChange where
  finalized : Bool
  activationHeight : Nat
  previousRoot : Digest
  nextRoot : Digest
  deriving BEq, DecidableEq, Repr

structure ProtocolUpgrade where
  finalized : Bool
  activationHeight : Nat
  previousRevision : Revision
  nextRevision : Revision
  deriving BEq, DecidableEq, Repr

structure TrustEvidence where
  qc : QuorumCertificate
  checkpoint : Checkpoint
  validatorChange : ValidatorSetChange
  upgrade : ProtocolUpgrade
  stateProofValid : Bool
  availabilityProofValid : Bool
  availabilityPayloadCommitment : Digest
  deriving BEq, DecidableEq, Repr

def validatorSetAllowed
    (current : TrustedHead) (candidate : Candidate)
    (change : ValidatorSetChange) : Prop :=
  candidate.validatorSetRoot = current.validatorSetRoot ∨
    (change.finalized = true ∧
      change.activationHeight = candidate.height ∧
      change.previousRoot = current.validatorSetRoot ∧
      change.nextRoot = candidate.validatorSetRoot)

def revisionAllowed
    (current : TrustedHead) (candidate : Candidate)
    (upgrade : ProtocolUpgrade) : Prop :=
  candidate.revision = current.revision ∨
    (upgrade.finalized = true ∧
      upgrade.activationHeight = candidate.height ∧
      upgrade.previousRevision = current.revision ∧
      upgrade.nextRevision = candidate.revision)

instance validatorSetAllowedDecidable
    (current : TrustedHead) (candidate : Candidate) (change : ValidatorSetChange) :
    Decidable (validatorSetAllowed current candidate change) := by
  unfold validatorSetAllowed
  infer_instance

instance revisionAllowedDecidable
    (current : TrustedHead) (candidate : Candidate) (upgrade : ProtocolUpgrade) :
    Decidable (revisionAllowed current candidate upgrade) := by
  unfold revisionAllowed
  infer_instance

def Candidate.BoundBy
    (candidate : Candidate) (evidence : TrustEvidence) : Prop :=
  evidence.qc.valid = true ∧
    evidence.qc.height = candidate.height ∧
    evidence.qc.stateRoot = candidate.stateRoot ∧
    evidence.qc.validatorSetRoot = candidate.validatorSetRoot ∧
    evidence.qc.revision = candidate.revision ∧
    evidence.checkpoint.height = candidate.height ∧
    evidence.checkpoint.stateRoot = candidate.stateRoot ∧
    evidence.checkpoint.validatorSetRoot = candidate.validatorSetRoot ∧
    evidence.checkpoint.revision = candidate.revision ∧
    evidence.checkpoint.payloadCommitment = candidate.payloadCommitment ∧
    evidence.stateProofValid = true ∧
    evidence.availabilityProofValid = true ∧
    evidence.availabilityPayloadCommitment = candidate.payloadCommitment

instance candidateBoundByDecidable (candidate : Candidate) (evidence : TrustEvidence) :
    Decidable (candidate.BoundBy evidence) := by
  unfold Candidate.BoundBy
  infer_instance

def TrustTransitionValid
    (current : TrustedHead) (candidate : Candidate)
    (evidence : TrustEvidence) : Prop :=
  current.height < candidate.height ∧
    validatorSetAllowed current candidate evidence.validatorChange ∧
    revisionAllowed current candidate evidence.upgrade ∧
    candidate.BoundBy evidence

def verifyTrustTransition
    (current : TrustedHead) (candidate : Candidate)
    (evidence : TrustEvidence) : Bool :=
  decide (current.height < candidate.height) &&
    decide (validatorSetAllowed current candidate evidence.validatorChange) &&
    decide (revisionAllowed current candidate evidence.upgrade) &&
    decide (candidate.BoundBy evidence)

theorem verifyTrustTransition_iff
    (current : TrustedHead) (candidate : Candidate) (evidence : TrustEvidence) :
    verifyTrustTransition current candidate evidence = true ↔
      TrustTransitionValid current candidate evidence := by
  simp [verifyTrustTransition, TrustTransitionValid, and_assoc]

def Candidate.toTrustedHead (candidate : Candidate) : TrustedHead :=
  {
    height := candidate.height
    stateRoot := candidate.stateRoot
    validatorSetRoot := candidate.validatorSetRoot
    revision := candidate.revision
  }

def advanceTrust
    (current : TrustedHead) (candidate : Candidate)
    (evidence : TrustEvidence) : Option TrustedHead :=
  if verifyTrustTransition current candidate evidence then
    some candidate.toTrustedHead
  else
    none

theorem successfulAdvanceSatisfiesEveryRequirement
    (current post : TrustedHead) (candidate : Candidate) (evidence : TrustEvidence)
    (accepted : advanceTrust current candidate evidence = some post) :
    TrustTransitionValid current candidate evidence := by
  unfold advanceTrust at accepted
  split at accepted
  next verified =>
    exact (verifyTrustTransition_iff current candidate evidence).mp verified
  next rejected => simp at accepted

theorem successfulAdvanceIsMonotonic
    (current post : TrustedHead) (candidate : Candidate) (evidence : TrustEvidence)
    (accepted : advanceTrust current candidate evidence = some post) :
    current.height < post.height := by
  have valid := successfulAdvanceSatisfiesEveryRequirement current post candidate evidence accepted
  unfold advanceTrust at accepted
  split at accepted
  next =>
    simp at accepted
    subst post
    exact valid.1
  next => simp at accepted

theorem missingAvailabilityCannotAdvance
    (current : TrustedHead) (candidate : Candidate) (evidence : TrustEvidence)
    (missing : evidence.availabilityProofValid = false) :
    advanceTrust current candidate evidence = none := by
  have notBound : ¬ candidate.BoundBy evidence := by
    intro bound
    have required := bound.2.2.2.2.2.2.2.2.2.2.2.1
    simp [missing] at required
  cases verified : verifyTrustTransition current candidate evidence with
  | false => simp [advanceTrust, verified]
  | true =>
      have valid := (verifyTrustTransition_iff current candidate evidence).mp verified
      exact False.elim (notBound valid.2.2.2)

theorem revisionChangeRequiresFinalizedActivation
    (current post : TrustedHead) (candidate : Candidate) (evidence : TrustEvidence)
    (changed : candidate.revision ≠ current.revision)
    (accepted : advanceTrust current candidate evidence = some post) :
    evidence.upgrade.finalized = true ∧
      evidence.upgrade.activationHeight = candidate.height ∧
      evidence.upgrade.previousRevision = current.revision ∧
      evidence.upgrade.nextRevision = candidate.revision := by
  have valid := successfulAdvanceSatisfiesEveryRequirement current post candidate evidence accepted
  rcases valid.2.2.1 with unchanged | upgraded
  · exact False.elim (changed unchanged)
  · exact upgraded

theorem validatorSetChangeRequiresFinalizedActivation
    (current post : TrustedHead) (candidate : Candidate) (evidence : TrustEvidence)
    (changed : candidate.validatorSetRoot ≠ current.validatorSetRoot)
    (accepted : advanceTrust current candidate evidence = some post) :
    evidence.validatorChange.finalized = true ∧
      evidence.validatorChange.activationHeight = candidate.height ∧
      evidence.validatorChange.previousRoot = current.validatorSetRoot ∧
      evidence.validatorChange.nextRoot = candidate.validatorSetRoot := by
  have valid := successfulAdvanceSatisfiesEveryRequirement current post candidate evidence accepted
  rcases valid.2.1 with unchanged | changedByEvidence
  · exact False.elim (changed unchanged)
  · exact changedByEvidence

end ActiveChain.DA
