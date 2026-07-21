/-!
# ActiveChain canonical finalized-block composition model

This dependency-free model makes the finalized-block boundary one atomic
predicate.  A successful finalization must connect one strictly decoded block
envelope to the expected chain context, deterministic authorization and
execution results, economics, post-state, data availability, execution-proof
public inputs, and the exact digest certified by a quorum certificate.

The model deliberately treats codecs, commitment functions, authorization,
execution, proof verification, and certificate verification as parameters.
Theorems which turn digest equality into object equality take the required
injectivity properties as explicit premises.
-/

namespace ActiveChain.BlockComposition

abbrev Byte := Fin 256
abbrev Digest := Nat
abbrev ChainId := Nat
abbrev Revision := Nat
abbrev Epoch := Nat
abbrev Height := Nat
abbrev Supply := Nat

/-! ## Canonical wire values and protocol artifacts -/

structure ChainContext where
  chainId : ChainId
  protocolRevision : Revision
  epoch : Epoch
  validatorSetRoot : Digest
  height : Height
  parentBlockDigest : Digest
  preStateRoot : Digest
  preSupply : Supply
  deriving BEq, DecidableEq, Repr

structure Action where
  kind : Nat
  payload : List Byte
  deriving BEq, DecidableEq, Repr

structure AuthorizationResult where
  decisions : List Bool
  witnessCommitment : Digest
  deriving BEq, DecidableEq, Repr

/-- Every decoded action has exactly one positive authorization decision. -/
def AuthorizationResult.Covers
    (authorization : AuthorizationResult) (actions : List Action) : Prop :=
  authorization.decisions.length = actions.length ∧
    authorization.decisions.all id = true

instance authorizationCoversDecidable
    (authorization : AuthorizationResult) (actions : List Action) :
    Decidable (authorization.Covers actions) := by
  unfold AuthorizationResult.Covers
  infer_instance

/-- Subtraction-free native-supply accounting for one block. -/
structure EconomicsTransition where
  preSupply : Supply
  feesCharged : Nat
  issuance : Nat
  feeBurn : Nat
  postSupply : Supply
  deriving BEq, DecidableEq, Repr

/-- Fees may be redistributed, but any fee burn is bounded by charged fees;
only declared issuance and fee burn may change total supply in this slice. -/
def EconomicsTransition.Valid
    (expectedPreSupply : Supply) (economics : EconomicsTransition) : Prop :=
  economics.preSupply = expectedPreSupply ∧
    economics.feeBurn ≤ economics.feesCharged ∧
    economics.postSupply + economics.feeBurn =
      economics.preSupply + economics.issuance

instance economicsValidDecidable
    (expectedPreSupply : Supply) (economics : EconomicsTransition) :
    Decidable (economics.Valid expectedPreSupply) := by
  unfold EconomicsTransition.Valid
  infer_instance

structure ExecutionResult where
  executedActions : List Action
  executionOrder : List Nat
  economics : EconomicsTransition
  postState : List Byte
  deriving BEq, DecidableEq, Repr

/-- A length-complete, duplicate-free, in-range execution order is a
permutation of all decoded action indices. -/
def CanonicalExecutionOrder (actions : List Action) (order : List Nat) : Prop :=
  order.length = actions.length ∧
    order.Nodup ∧
    order.all (fun index => decide (index < actions.length)) = true

instance canonicalExecutionOrderDecidable (actions : List Action) (order : List Nat) :
    Decidable (CanonicalExecutionOrder actions order) := by
  unfold CanonicalExecutionOrder
  infer_instance

structure ProofPublicInputs where
  context : ChainContext
  authorizationRoot : Digest
  actionRoot : Digest
  executionOrderRoot : Digest
  economics : EconomicsTransition
  postStateRoot : Digest
  dataAvailabilityCommitment : Digest
  deriving BEq, DecidableEq, Repr

structure ProofStatement where
  vmRevision : Revision
  programCommitment : Digest
  publicInputs : ProofPublicInputs
  deriving BEq, DecidableEq, Repr

structure ExecutionProof where
  statement : ProofStatement
  proofBytes : List Byte
  deriving BEq, DecidableEq, Repr

/-- The header contains every public value which execution and availability
must bind.  The proof-statement commitment excludes proof bytes, allowing
different encodings of a proof for the same immutable statement. -/
structure BlockHeader where
  context : ChainContext
  authorizationRoot : Digest
  actionRoot : Digest
  executionOrderRoot : Digest
  economics : EconomicsTransition
  postStateRoot : Digest
  dataAvailabilityCommitment : Digest
  proofStatementCommitment : Digest
  deriving BEq, DecidableEq, Repr

structure WireBlock where
  typeTag : Nat
  schemaVersion : Nat
  header : BlockHeader
  actions : List Action
  deriving BEq, DecidableEq, Repr

structure QuorumCertificate where
  chainId : ChainId
  protocolRevision : Revision
  epoch : Epoch
  validatorSetRoot : Digest
  height : Height
  certifiedBlockDigest : Digest
  deriving BEq, DecidableEq, Repr

/-! ## Strict codec and deterministic protocol boundary -/

structure CanonicalCodec where
  encode : WireBlock → List Byte
  decode : List Byte → Option WireBlock

/-- A decoder result is accepted only when re-encoding the decoded value
reproduces every input byte.  Thus incomplete, non-canonical, or trailing-byte
representations are rejected even if the underlying decoder is permissive. -/
def strictDecode (codec : CanonicalCodec) (encoded : List Byte) : Option WireBlock :=
  match codec.decode encoded with
  | none => none
  | some block =>
      if codec.encode block = encoded then some block else none

structure CommitmentFunctions where
  authorization : ChainContext → List Action → AuthorizationResult → Digest
  actions : List Action → Digest
  executionOrder : List Nat → Digest
  postState : List Byte → Digest
  dataAvailability : List Byte → Digest
  proofStatement : ProofStatement → Digest
  header : BlockHeader → Digest

structure ProtocolBoundary where
  codec : CanonicalCodec
  commitments : CommitmentFunctions
  expectedTypeTag : Nat
  expectedSchemaVersion : Nat
  expectedContext : ChainContext
  authorize : ChainContext → List Action → AuthorizationResult
  execute : ChainContext → List Action → AuthorizationResult → ExecutionResult
  encodeAvailability :
    ChainContext → List Action → AuthorizationResult → ExecutionResult → List Byte
  verifyExecutionProof : ProofStatement → List Byte → Bool
  verifyQuorumCertificate : QuorumCertificate → Bool

def publicInputsFor (header : BlockHeader) : ProofPublicInputs :=
  {
    context := header.context
    authorizationRoot := header.authorizationRoot
    actionRoot := header.actionRoot
    executionOrderRoot := header.executionOrderRoot
    economics := header.economics
    postStateRoot := header.postStateRoot
    dataAvailabilityCommitment := header.dataAvailabilityCommitment
  }

structure Candidate where
  encodedEnvelope : List Byte
  wire : WireBlock
  authorization : AuthorizationResult
  execution : ExecutionResult
  availabilityPayload : List Byte
  proof : ExecutionProof
  certificate : QuorumCertificate
  deriving BEq, DecidableEq, Repr

/-! ## Complete finalization predicate -/

def CanonicalBinding (protocol : ProtocolBoundary) (candidate : Candidate) : Prop :=
  strictDecode protocol.codec candidate.encodedEnvelope = some candidate.wire ∧
    candidate.wire.typeTag = protocol.expectedTypeTag ∧
    candidate.wire.schemaVersion = protocol.expectedSchemaVersion

def ContextBinding (protocol : ProtocolBoundary) (candidate : Candidate) : Prop :=
  candidate.wire.header.context = protocol.expectedContext

def AuthorizationBinding (protocol : ProtocolBoundary) (candidate : Candidate) : Prop :=
  candidate.authorization =
      protocol.authorize protocol.expectedContext candidate.wire.actions ∧
    candidate.authorization.Covers candidate.wire.actions ∧
    candidate.wire.header.authorizationRoot =
      protocol.commitments.authorization protocol.expectedContext
        candidate.wire.actions candidate.authorization

def ExecutionBinding (protocol : ProtocolBoundary) (candidate : Candidate) : Prop :=
  candidate.execution =
      protocol.execute protocol.expectedContext candidate.wire.actions
        candidate.authorization ∧
    candidate.execution.executedActions = candidate.wire.actions ∧
    CanonicalExecutionOrder candidate.wire.actions candidate.execution.executionOrder ∧
    candidate.execution.economics.Valid protocol.expectedContext.preSupply ∧
    candidate.wire.header.actionRoot =
      protocol.commitments.actions candidate.execution.executedActions ∧
    candidate.wire.header.executionOrderRoot =
      protocol.commitments.executionOrder candidate.execution.executionOrder ∧
    candidate.wire.header.economics = candidate.execution.economics ∧
    candidate.wire.header.postStateRoot =
      protocol.commitments.postState candidate.execution.postState

def AvailabilityBinding (protocol : ProtocolBoundary) (candidate : Candidate) : Prop :=
  candidate.availabilityPayload =
      protocol.encodeAvailability protocol.expectedContext candidate.wire.actions
        candidate.authorization candidate.execution ∧
    candidate.wire.header.dataAvailabilityCommitment =
      protocol.commitments.dataAvailability candidate.availabilityPayload

def ProofBinding (protocol : ProtocolBoundary) (candidate : Candidate) : Prop :=
  candidate.proof.statement.publicInputs = publicInputsFor candidate.wire.header ∧
    candidate.wire.header.proofStatementCommitment =
      protocol.commitments.proofStatement candidate.proof.statement ∧
    protocol.verifyExecutionProof candidate.proof.statement candidate.proof.proofBytes = true

def CertificateBinding (protocol : ProtocolBoundary) (candidate : Candidate) : Prop :=
  candidate.certificate.chainId = candidate.wire.header.context.chainId ∧
    candidate.certificate.protocolRevision =
      candidate.wire.header.context.protocolRevision ∧
    candidate.certificate.epoch = candidate.wire.header.context.epoch ∧
    candidate.certificate.validatorSetRoot =
      candidate.wire.header.context.validatorSetRoot ∧
    candidate.certificate.height = candidate.wire.header.context.height ∧
    candidate.certificate.certifiedBlockDigest =
      protocol.commitments.header candidate.wire.header ∧
    protocol.verifyQuorumCertificate candidate.certificate = true

def CandidateValid (protocol : ProtocolBoundary) (candidate : Candidate) : Prop :=
  CanonicalBinding protocol candidate ∧
    ContextBinding protocol candidate ∧
    AuthorizationBinding protocol candidate ∧
    ExecutionBinding protocol candidate ∧
    AvailabilityBinding protocol candidate ∧
    ProofBinding protocol candidate ∧
    CertificateBinding protocol candidate

instance candidateValidDecidable (protocol : ProtocolBoundary) (candidate : Candidate) :
    Decidable (CandidateValid protocol candidate) := by
  unfold CandidateValid CanonicalBinding ContextBinding AuthorizationBinding
    ExecutionBinding AvailabilityBinding ProofBinding CertificateBinding
  infer_instance

namespace CandidateValid

theorem canonical {protocol : ProtocolBoundary} {candidate : Candidate}
    (valid : CandidateValid protocol candidate) : CanonicalBinding protocol candidate :=
  valid.1

theorem context {protocol : ProtocolBoundary} {candidate : Candidate}
    (valid : CandidateValid protocol candidate) : ContextBinding protocol candidate :=
  valid.2.1

theorem authorization {protocol : ProtocolBoundary} {candidate : Candidate}
    (valid : CandidateValid protocol candidate) : AuthorizationBinding protocol candidate :=
  valid.2.2.1

theorem execution {protocol : ProtocolBoundary} {candidate : Candidate}
    (valid : CandidateValid protocol candidate) : ExecutionBinding protocol candidate :=
  valid.2.2.2.1

theorem availability {protocol : ProtocolBoundary} {candidate : Candidate}
    (valid : CandidateValid protocol candidate) : AvailabilityBinding protocol candidate :=
  valid.2.2.2.2.1

theorem proof {protocol : ProtocolBoundary} {candidate : Candidate}
    (valid : CandidateValid protocol candidate) : ProofBinding protocol candidate :=
  valid.2.2.2.2.2.1

theorem certificate {protocol : ProtocolBoundary} {candidate : Candidate}
    (valid : CandidateValid protocol candidate) : CertificateBinding protocol candidate :=
  valid.2.2.2.2.2.2

end CandidateValid

structure FinalizedBlock where
  header : BlockHeader
  blockDigest : Digest
  actions : List Action
  authorization : AuthorizationResult
  executionOrder : List Nat
  economics : EconomicsTransition
  postState : List Byte
  availabilityPayload : List Byte
  proofStatement : ProofStatement
  deriving BEq, DecidableEq, Repr

theorem FinalizedBlock.equalOfFields
    (left right : FinalizedBlock)
    (sameHeader : left.header = right.header)
    (sameBlockDigest : left.blockDigest = right.blockDigest)
    (sameActions : left.actions = right.actions)
    (sameAuthorization : left.authorization = right.authorization)
    (sameExecutionOrder : left.executionOrder = right.executionOrder)
    (sameEconomics : left.economics = right.economics)
    (samePostState : left.postState = right.postState)
    (sameAvailabilityPayload :
      left.availabilityPayload = right.availabilityPayload)
    (sameProofStatement : left.proofStatement = right.proofStatement) :
    left = right := by
  cases left
  cases right
  simp_all

def finalizedBlockOf (candidate : Candidate) : FinalizedBlock :=
  {
    header := candidate.wire.header
    blockDigest := candidate.certificate.certifiedBlockDigest
    actions := candidate.wire.actions
    authorization := candidate.authorization
    executionOrder := candidate.execution.executionOrder
    economics := candidate.execution.economics
    postState := candidate.execution.postState
    availabilityPayload := candidate.availabilityPayload
    proofStatement := candidate.proof.statement
  }

def finalize
    (protocol : ProtocolBoundary) (candidate : Candidate) : Option FinalizedBlock :=
  if CandidateValid protocol candidate then
    some (finalizedBlockOf candidate)
  else
    none

theorem finalize_ok_iff (protocol : ProtocolBoundary) (candidate : Candidate) :
    finalize protocol candidate = some (finalizedBlockOf candidate) ↔
      CandidateValid protocol candidate := by
  simp [finalize]

theorem successfulFinalizationIsValid
    (protocol : ProtocolBoundary) (candidate : Candidate) (result : FinalizedBlock)
    (accepted : finalize protocol candidate = some result) :
    CandidateValid protocol candidate := by
  unfold finalize at accepted
  split at accepted
  · assumption
  · simp at accepted

theorem successfulFinalizationReturnsCanonicalResult
    (protocol : ProtocolBoundary) (candidate : Candidate) (result : FinalizedBlock)
    (accepted : finalize protocol candidate = some result) :
    result = finalizedBlockOf candidate := by
  unfold finalize at accepted
  split at accepted
  · exact Option.some.inj accepted |>.symm
  · simp at accepted

/-- Successful finalization exposes all seven independently reviewable
bindings, rather than merely recording a success marker. -/
theorem successfulFinalizationBindsImmutableBlock
    (protocol : ProtocolBoundary) (candidate : Candidate) (result : FinalizedBlock)
    (accepted : finalize protocol candidate = some result) :
    CanonicalBinding protocol candidate ∧
      ContextBinding protocol candidate ∧
      AuthorizationBinding protocol candidate ∧
      ExecutionBinding protocol candidate ∧
      AvailabilityBinding protocol candidate ∧
      ProofBinding protocol candidate ∧
      CertificateBinding protocol candidate := by
  exact successfulFinalizationIsValid protocol candidate result accepted

/-! ## Rejection of every unbound component -/

theorem invalidCandidateIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (invalid : ¬ CandidateValid protocol candidate) :
    finalize protocol candidate = none := by
  simp [finalize, invalid]

theorem anyBindingMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      ¬ CanonicalBinding protocol candidate ∨
      ¬ ContextBinding protocol candidate ∨
      ¬ AuthorizationBinding protocol candidate ∨
      ¬ ExecutionBinding protocol candidate ∨
      ¬ AvailabilityBinding protocol candidate ∨
      ¬ ProofBinding protocol candidate ∨
      ¬ CertificateBinding protocol candidate) :
    finalize protocol candidate = none := by
  apply invalidCandidateIsRejected
  intro valid
  rcases mismatch with canonical | context | authorization | execution |
      availability | proof | certificate
  · exact canonical valid.canonical
  · exact context valid.context
  · exact authorization valid.authorization
  · exact execution valid.execution
  · exact availability valid.availability
  · exact proof valid.proof
  · exact certificate valid.certificate

theorem nonCanonicalEnvelopeIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      strictDecode protocol.codec candidate.encodedEnvelope ≠ some candidate.wire) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  left
  intro canonical
  exact mismatch canonical.1

theorem wrongTypeTagIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch : candidate.wire.typeTag ≠ protocol.expectedTypeTag) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  left
  intro canonical
  exact mismatch canonical.2.1

theorem wrongSchemaVersionIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch : candidate.wire.schemaVersion ≠ protocol.expectedSchemaVersion) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  left
  intro canonical
  exact mismatch canonical.2.2

theorem wrongProtocolRevisionIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.wire.header.context.protocolRevision ≠
        protocol.expectedContext.protocolRevision) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; left
  intro context
  exact mismatch (congrArg ChainContext.protocolRevision context)

theorem wrongHeightIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.wire.header.context.height ≠ protocol.expectedContext.height) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; left
  intro context
  exact mismatch (congrArg ChainContext.height context)

theorem wrongParentDigestIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.wire.header.context.parentBlockDigest ≠
        protocol.expectedContext.parentBlockDigest) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; left
  intro context
  exact mismatch (congrArg ChainContext.parentBlockDigest context)

theorem wrongChainContextIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch : candidate.wire.header.context ≠ protocol.expectedContext) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; left
  exact mismatch

theorem authorizationMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.authorization ≠
        protocol.authorize protocol.expectedContext candidate.wire.actions) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; left
  intro authorization
  exact mismatch authorization.1

theorem authorizationRootMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.wire.header.authorizationRoot ≠
        protocol.commitments.authorization protocol.expectedContext
          candidate.wire.actions candidate.authorization) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; left
  intro authorization
  exact mismatch authorization.2.2

theorem executionResultMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.execution ≠
        protocol.execute protocol.expectedContext candidate.wire.actions
          candidate.authorization) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; left
  intro execution
  exact mismatch execution.1

theorem actionRootMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.wire.header.actionRoot ≠
        protocol.commitments.actions candidate.execution.executedActions) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; left
  intro execution
  exact mismatch execution.2.2.2.2.1

theorem executionOrderRootMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.wire.header.executionOrderRoot ≠
        protocol.commitments.executionOrder candidate.execution.executionOrder) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; left
  intro execution
  exact mismatch execution.2.2.2.2.2.1

theorem economicsMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch : candidate.wire.header.economics ≠ candidate.execution.economics) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; left
  intro execution
  exact mismatch execution.2.2.2.2.2.2.1

theorem invalidSupplyTransitionIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (invalid :
      ¬ candidate.execution.economics.Valid protocol.expectedContext.preSupply) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; left
  intro execution
  exact invalid execution.2.2.2.1

theorem postStateRootMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.wire.header.postStateRoot ≠
        protocol.commitments.postState candidate.execution.postState) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; left
  intro execution
  exact mismatch execution.2.2.2.2.2.2.2

theorem availabilityCommitmentMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.wire.header.dataAvailabilityCommitment ≠
        protocol.commitments.dataAvailability candidate.availabilityPayload) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; right; left
  intro availability
  exact mismatch availability.2

theorem availabilityPayloadMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.availabilityPayload ≠
        protocol.encodeAvailability protocol.expectedContext candidate.wire.actions
          candidate.authorization candidate.execution) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; right; left
  intro availability
  exact mismatch availability.1

theorem proofPublicInputsMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.proof.statement.publicInputs ≠ publicInputsFor candidate.wire.header) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; right; right; left
  intro proof
  exact mismatch proof.1

theorem proofStatementCommitmentMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.wire.header.proofStatementCommitment ≠
        protocol.commitments.proofStatement candidate.proof.statement) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; right; right; left
  intro proof
  exact mismatch proof.2.1

theorem rejectedExecutionProofCannotFinalize
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (rejected :
      protocol.verifyExecutionProof candidate.proof.statement candidate.proof.proofBytes ≠
        true) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; right; right; left
  intro proof
  exact rejected proof.2.2

theorem certifiedDigestMismatchIsRejected
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (mismatch :
      candidate.certificate.certifiedBlockDigest ≠
        protocol.commitments.header candidate.wire.header) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; right; right; right
  intro certificate
  exact mismatch certificate.2.2.2.2.2.1

theorem rejectedQuorumCertificateCannotFinalize
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (rejected : protocol.verifyQuorumCertificate candidate.certificate ≠ true) :
    finalize protocol candidate = none := by
  apply anyBindingMismatchIsRejected protocol candidate
  right; right; right; right; right; right
  intro certificate
  exact rejected certificate.2.2.2.2.2.2

/-! ## Determinism and collision-conditional uniqueness -/

/-- The finalization function has one result for one candidate. -/
theorem finalizationIsDeterministic
    (protocol : ProtocolBoundary) (candidate : Candidate)
    (left right : FinalizedBlock)
    (leftAccepted : finalize protocol candidate = some left)
    (rightAccepted : finalize protocol candidate = some right) :
    left = right := by
  exact Option.some.inj (leftAccepted.symm.trans rightAccepted)

/-- Strict decoding is deterministic across two candidates carrying the same
complete envelope; no codec injectivity premise is needed for this direction. -/
theorem sameAcceptedEnvelopeHasSameWireBlock
    (protocol : ProtocolBoundary) (left right : Candidate)
    (leftValid : CandidateValid protocol left)
    (rightValid : CandidateValid protocol right)
    (sameEnvelope : left.encodedEnvelope = right.encodedEnvelope) :
    left.wire = right.wire := by
  have leftDecode := leftValid.canonical.1
  have rightDecode := rightValid.canonical.1
  rw [sameEnvelope] at leftDecode
  exact Option.some.inj (leftDecode.symm.trans rightDecode)

/-- If the canonical encoder is injective, equal canonical bytes also identify
one wire block independently of decoder behavior. -/
theorem equalCanonicalEncodingHasSameWireBlock
    (codec : CanonicalCodec)
    (encodingInjective : Function.Injective codec.encode)
    (left right : WireBlock)
    (sameEncoding : codec.encode left = codec.encode right) :
    left = right :=
  encodingInjective sameEncoding

/-- Two successful candidates for the same exact header cannot expose
different post-states or proof statements, conditional only on the two
corresponding commitment functions being injective. -/
theorem sameHeaderCannotFinalizeDifferentStateOrProofStatement
    (protocol : ProtocolBoundary) (left right : Candidate)
    (leftResult rightResult : FinalizedBlock)
    (leftAccepted : finalize protocol left = some leftResult)
    (rightAccepted : finalize protocol right = some rightResult)
    (sameHeader : left.wire.header = right.wire.header)
    (postStateCommitmentInjective :
      Function.Injective protocol.commitments.postState)
    (proofStatementCommitmentInjective :
      Function.Injective protocol.commitments.proofStatement) :
    left.execution.postState = right.execution.postState ∧
      left.proof.statement = right.proof.statement := by
  have leftValid := successfulFinalizationIsValid protocol left leftResult leftAccepted
  have rightValid := successfulFinalizationIsValid protocol right rightResult rightAccepted
  have leftState := leftValid.execution.2.2.2.2.2.2.2
  have rightState := rightValid.execution.2.2.2.2.2.2.2
  have stateCommitmentsEqual :
      protocol.commitments.postState left.execution.postState =
        protocol.commitments.postState right.execution.postState := by
    rw [← leftState, ← rightState, sameHeader]
  have leftProof := leftValid.proof.2.1
  have rightProof := rightValid.proof.2.1
  have proofCommitmentsEqual :
      protocol.commitments.proofStatement left.proof.statement =
        protocol.commitments.proofStatement right.proof.statement := by
    rw [← leftProof, ← rightProof, sameHeader]
  exact
    ⟨postStateCommitmentInjective stateCommitmentsEqual,
      proofStatementCommitmentInjective proofCommitmentsEqual⟩

/-- Equality of the digest observed in two valid certificates first identifies
one header under the explicit header-commitment injectivity premise, then the
state and proof-statement premises identify the underlying committed values. -/
theorem sameCertifiedDigestCannotFinalizeDifferentStateOrProofStatement
    (protocol : ProtocolBoundary) (left right : Candidate)
    (leftResult rightResult : FinalizedBlock)
    (leftAccepted : finalize protocol left = some leftResult)
    (rightAccepted : finalize protocol right = some rightResult)
    (sameCertifiedDigest :
      left.certificate.certifiedBlockDigest = right.certificate.certifiedBlockDigest)
    (headerCommitmentInjective : Function.Injective protocol.commitments.header)
    (postStateCommitmentInjective :
      Function.Injective protocol.commitments.postState)
    (proofStatementCommitmentInjective :
      Function.Injective protocol.commitments.proofStatement) :
    left.execution.postState = right.execution.postState ∧
      left.proof.statement = right.proof.statement := by
  have leftValid := successfulFinalizationIsValid protocol left leftResult leftAccepted
  have rightValid := successfulFinalizationIsValid protocol right rightResult rightAccepted
  have leftCertificateDigest := leftValid.certificate.2.2.2.2.2.1
  have rightCertificateDigest := rightValid.certificate.2.2.2.2.2.1
  have headerCommitmentsEqual :
      protocol.commitments.header left.wire.header =
        protocol.commitments.header right.wire.header := by
    rw [← leftCertificateDigest, ← rightCertificateDigest, sameCertifiedDigest]
  have sameHeader := headerCommitmentInjective headerCommitmentsEqual
  exact sameHeaderCannotFinalizeDifferentStateOrProofStatement
    protocol left right leftResult rightResult leftAccepted rightAccepted sameHeader
      postStateCommitmentInjective proofStatementCommitmentInjective

/-- Under proof-statement commitment injectivity, successful candidates with
the same strict envelope materialize the same finalized block.  Authorization,
execution, state, economics, and availability equality follow from the shared
wire block and deterministic protocol functions; proof bytes are deliberately
not part of finalized block identity. -/
theorem sameEnvelopeFinalizationIsDeterministic
    (protocol : ProtocolBoundary) (left right : Candidate)
    (leftResult rightResult : FinalizedBlock)
    (leftAccepted : finalize protocol left = some leftResult)
    (rightAccepted : finalize protocol right = some rightResult)
    (sameEnvelope : left.encodedEnvelope = right.encodedEnvelope)
    (proofStatementCommitmentInjective :
      Function.Injective protocol.commitments.proofStatement) :
    leftResult = rightResult := by
  have leftValid := successfulFinalizationIsValid protocol left leftResult leftAccepted
  have rightValid := successfulFinalizationIsValid protocol right rightResult rightAccepted
  have sameWire :=
    sameAcceptedEnvelopeHasSameWireBlock protocol left right leftValid rightValid sameEnvelope
  have sameAuthorization : left.authorization = right.authorization := by
    rw [leftValid.authorization.1, rightValid.authorization.1, sameWire]
  have sameExecution : left.execution = right.execution := by
    rw [leftValid.execution.1, rightValid.execution.1, sameWire, sameAuthorization]
  have sameAvailability : left.availabilityPayload = right.availabilityPayload := by
    rw [leftValid.availability.1, rightValid.availability.1, sameWire,
      sameAuthorization, sameExecution]
  have sameProofStatement : left.proof.statement = right.proof.statement := by
    apply proofStatementCommitmentInjective
    rw [← leftValid.proof.2.1, ← rightValid.proof.2.1, sameWire]
  have sameDigest :
      left.certificate.certifiedBlockDigest =
        right.certificate.certifiedBlockDigest := by
    rw [leftValid.certificate.2.2.2.2.2.1,
      rightValid.certificate.2.2.2.2.2.1, sameWire]
  rw [successfulFinalizationReturnsCanonicalResult protocol left leftResult leftAccepted,
    successfulFinalizationReturnsCanonicalResult protocol right rightResult rightAccepted]
  apply FinalizedBlock.equalOfFields
  · exact congrArg WireBlock.header sameWire
  · exact sameDigest
  · exact congrArg WireBlock.actions sameWire
  · exact sameAuthorization
  · exact congrArg ExecutionResult.executionOrder sameExecution
  · exact congrArg ExecutionResult.economics sameExecution
  · exact congrArg ExecutionResult.postState sameExecution
  · exact sameAvailability
  · exact sameProofStatement

end ActiveChain.BlockComposition
