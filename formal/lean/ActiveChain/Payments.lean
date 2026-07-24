/-!
# ActiveBridge payment lifecycle model

This model fixes terminal immutability, exact sequence advancement, and the distinction between an
external confirmation and ActiveChain finality. Cryptographic authenticity, canonical decoding,
provider honesty, and Rust-to-Lean refinement remain explicit external assumptions.
-/

namespace ActiveChain.Payments

inductive State where
  | created
  | awaitingPayer
  | providerPending
  | externallyConfirmed
  | chainSubmitted
  | finalized
  | refundPending
  | refunded
  | expired
  | rejected
  | failed
  | cancelled
  | manualReview
  deriving BEq, DecidableEq, Repr

inductive Evidence where
  | untrustedClient
  | connectorAuthenticated
  | providerSigned
  | regulatedAttestation
  | activeChainFinalized
  deriving BEq, DecidableEq, Repr

def isTerminal : State → Bool
  | .refunded | .expired | .rejected | .failed | .cancelled => true
  | _ => false

def permits : State → State → Bool
  | .created, next => next == .awaitingPayer || next == .cancelled || next == .expired
  | .awaitingPayer, next =>
      next == .providerPending || next == .cancelled || next == .expired || next == .rejected
  | .providerPending, next =>
      next == .externallyConfirmed || next == .failed || next == .expired ||
        next == .manualReview
  | .externallyConfirmed, next =>
      next == .chainSubmitted || next == .failed || next == .manualReview
  | .chainSubmitted, next =>
      next == .finalized || next == .rejected || next == .failed || next == .manualReview
  | .finalized, next => next == .refundPending
  | .refundPending, next => next == .refunded || next == .failed || next == .manualReview
  | .manualReview, next =>
      next == .providerPending || next == .externallyConfirmed || next == .chainSubmitted ||
        next == .refundPending || next == .rejected || next == .failed || next == .cancelled
  | _, _ => false

structure Record where
  intent : Nat
  sequence : Nat
  state : State
  evidence : Evidence
  transaction : Option Nat
  finalizedHeight : Nat
  finalizedBlock : Option Nat
  deriving BEq, DecidableEq, Repr

def isFinalizedEvidence : Evidence → Bool
  | .activeChainFinalized => true
  | _ => false

def hasFinality (record : Record) : Bool :=
  isFinalizedEvidence record.evidence &&
    record.transaction.isSome &&
    record.finalizedHeight != 0 &&
    record.finalizedBlock.isSome

def wellFormed (record : Record) : Bool :=
  record.intent != 0 && record.sequence != 0 &&
    match record.state with
    | .finalized | .refunded => hasFinality record
    | .chainSubmitted =>
        !isFinalizedEvidence record.evidence &&
          record.finalizedHeight == 0 &&
          record.finalizedBlock.isNone &&
          record.transaction.isSome
    | _ =>
        !isFinalizedEvidence record.evidence &&
          record.finalizedHeight == 0 &&
          record.finalizedBlock.isNone &&
          record.transaction.isNone

def follows (previous next : Record) : Bool :=
  previous.intent == next.intent &&
    next.sequence == previous.sequence + 1 &&
    permits previous.state next.state

theorem terminalHasNoSuccessor
    (state next : State)
    (hTerminal : isTerminal state = true) :
    permits state next = false := by
  cases state <;> cases next <;> simp_all [isTerminal, permits]

theorem successorsAdvanceExactlyOne
    (previous next : Record)
    (h : follows previous next = true) :
    next.sequence = previous.sequence + 1 := by
  simp [follows] at h
  exact h.1.2

theorem externalConfirmationIsNotFinality
    (record : Record)
    (hState : record.state = .externallyConfirmed)
    (hWellFormed : wellFormed record = true) :
    record.evidence ≠ .activeChainFinalized := by
  cases record with
  | mk intent sequence state evidence transaction height block =>
      cases state <;> cases evidence <;> simp_all [wellFormed, isFinalizedEvidence]

theorem finalizedCarriesFinality
    (record : Record)
    (hState : record.state = .finalized)
    (hWellFormed : wellFormed record = true) :
    hasFinality record = true := by
  cases record with
  | mk intent sequence state evidence transaction height block =>
      cases state <;> simp_all [wellFormed]

structure Observation where
  attempt : Nat
  sequence : Nat
  observedAt : Nat
  deriving BEq, DecidableEq, Repr

def observationFollows (previous next : Observation) : Bool :=
  previous.attempt == next.attempt &&
    next.sequence == previous.sequence + 1 &&
    previous.observedAt <= next.observedAt

theorem observationSuccessorPreservesAttemptAndSequence
    (previous next : Observation)
    (h : observationFollows previous next = true) :
    previous.attempt = next.attempt ∧ next.sequence = previous.sequence + 1 := by
  simp [observationFollows] at h
  exact h.1

def journalApply (current incoming : Observation) : Option Observation :=
  if current = incoming then some current
  else if observationFollows current incoming then some incoming
  else none

theorem exactObservationReplayDoesNotMutate (observation : Observation) :
    journalApply observation observation = some observation := by
  simp [journalApply]

theorem rejectedObservationLeavesNoReplacement
    (current incoming : Observation)
    (hDifferent : current ≠ incoming)
    (hRejected : observationFollows current incoming = false) :
    journalApply current incoming = none := by
  simp [journalApply, hDifferent, hRejected]

inductive ProviderState where
  | pending
  | succeeded
  | rejected
  | reversed
  | cancelled
  | unknown
  deriving BEq, DecidableEq, Repr

def providerPermits : ProviderState → ProviderState → Bool
  | .pending, next =>
      next == .pending || next == .succeeded || next == .rejected ||
        next == .cancelled || next == .unknown
  | .unknown, next =>
      next == .pending || next == .succeeded || next == .rejected || next == .cancelled
  | .succeeded, next => next == .reversed
  | _, _ => false

def providerTerminal : ProviderState → Bool
  | .rejected | .reversed | .cancelled => true
  | _ => false

theorem providerTerminalHasNoSuccessor
    (state next : ProviderState)
    (hTerminal : providerTerminal state = true) :
    providerPermits state next = false := by
  cases state <;> cases next <;> simp_all [providerTerminal, providerPermits]

def nextCursor (cursor length : Nat) : Nat :=
  if cursor + 1 < length then cursor + 1 else cursor

theorem simulatorCursorIsMonotonic (cursor length : Nat) :
    cursor ≤ nextCursor cursor length := by
  by_cases advances : cursor + 1 < length
  · simp [nextCursor, advances]
  · simp [nextCursor, advances]

inductive NtzsApiState where
  | depositSubmitted
  | transferCompleted
  | withdrawalRequested
  | withdrawalBurned
  | swapChecking
  | swapSending
  | swapFilling
  | swapFilled
  | swapFailed
  | rampPayingOut
  | rampMinting
  | rampCompleted
  | rampFailed
  | unrecognized
  deriving BEq, DecidableEq, Repr

def mapNtzsApiState : NtzsApiState → ProviderState
  | .depositSubmitted | .withdrawalRequested | .withdrawalBurned |
    .swapChecking | .swapSending | .swapFilling | .rampPayingOut | .rampMinting => .pending
  | .transferCompleted | .swapFilled | .rampCompleted => .succeeded
  | .swapFailed | .rampFailed => .rejected
  | .unrecognized => .unknown

theorem ntzsUnrecognizedFailsClosed :
    mapNtzsApiState .unrecognized = .unknown := by
  rfl

theorem ntzsWithdrawalBurnIsNotSuccess :
    mapNtzsApiState .withdrawalBurned ≠ .succeeded := by
  decide

theorem ntzsApiMappingIsBounded (state : NtzsApiState) :
    mapNtzsApiState state = .pending ||
      mapNtzsApiState state = .succeeded ||
      mapNtzsApiState state = .rejected ||
      mapNtzsApiState state = .unknown := by
  cases state <;> simp [mapNtzsApiState]

inductive NtzsWebhook where
  | depositCompleted
  | transferCompleted
  | withdrawalCompleted
  | unsupported
  deriving BEq, DecidableEq, Repr

def mapNtzsWebhook : NtzsWebhook → Option ProviderState
  | .depositCompleted | .transferCompleted | .withdrawalCompleted => some .succeeded
  | .unsupported => none

theorem ntzsUnsupportedWebhookIsNotAdmitted :
    mapNtzsWebhook .unsupported = none := by
  rfl

def ntzsWebhookEvidence : Evidence := .connectorAuthenticated

theorem ntzsWebhookIsNotFinality :
    ntzsWebhookEvidence ≠ .activeChainFinalized := by
  decide

structure ExactProviderAmount where
  coefficient : Nat
  scale : Nat
  deriving BEq, DecidableEq, Repr

def providerAtomicUnits (amount : ExactProviderAmount) (assetDecimals : Nat) : Option Nat :=
  if amount.scale ≤ assetDecimals then
    some (amount.coefficient * 10 ^ (assetDecimals - amount.scale))
  else
    none

theorem providerPrecisionAboveAssetIsRejected
    (amount : ExactProviderAmount)
    (assetDecimals : Nat)
    (hPrecision : assetDecimals < amount.scale) :
    providerAtomicUnits amount assetDecimals = none := by
  simp [providerAtomicUnits, Nat.not_le.mpr hPrecision]

def exactProviderAmountMatches
    (amount : ExactProviderAmount)
    (assetDecimals expectedAtomicUnits : Nat) : Bool :=
  providerAtomicUnits amount assetDecimals == some expectedAtomicUnits

theorem acceptedProviderAmountEqualsExpectedAtomicUnits
    (amount : ExactProviderAmount)
    (assetDecimals expectedAtomicUnits : Nat)
    (hAccepted : exactProviderAmountMatches amount assetDecimals expectedAtomicUnits = true) :
    providerAtomicUnits amount assetDecimals = some expectedAtomicUnits := by
  simpa [exactProviderAmountMatches] using hAccepted

structure ProviderResponseBinding where
  unit : Nat
  asset : Nat
  reference : Nat
  atomicUnits : Nat
  deriving BEq, DecidableEq, Repr

def exactProviderBindingMatches
    (provider expected : ProviderResponseBinding) : Prop :=
  provider.unit = expected.unit ∧
    provider.asset = expected.asset ∧
    provider.reference = expected.reference ∧
    provider.atomicUnits = expected.atomicUnits

theorem acceptedProviderBindingIsExact
    (provider expected : ProviderResponseBinding)
    (hAccepted : exactProviderBindingMatches provider expected) :
    provider = expected := by
  cases provider with
  | mk providerUnit providerAsset providerReference providerAmount =>
      cases expected with
      | mk expectedUnit expectedAsset expectedReference expectedAmount =>
          simp [exactProviderBindingMatches] at hAccepted
          rcases hAccepted with ⟨rfl, rfl, rfl, rfl⟩
          rfl

inductive NtzsAttemptPhase where
  | prepared
  | mayHaveReachedProvider
  | providerReferenceBound
  deriving BEq, DecidableEq, Repr

inductive NtzsDispatchDecision where
  | ready
  | reconcile
  | complete
  deriving BEq, DecidableEq, Repr

def ntzsDispatchDecision : NtzsAttemptPhase → NtzsDispatchDecision
  | .prepared => .ready
  | .mayHaveReachedProvider => .reconcile
  | .providerReferenceBound => .complete

theorem onlyPreparedAttemptIsReady (phase : NtzsAttemptPhase) :
    ntzsDispatchDecision phase = .ready ↔ phase = .prepared := by
  cases phase <;> simp [ntzsDispatchDecision]

theorem ambiguousAttemptCannotDispatchAgain :
    ntzsDispatchDecision .mayHaveReachedProvider = .reconcile := by
  rfl

def markNtzsDispatch : NtzsAttemptPhase → Option NtzsAttemptPhase
  | .prepared => some .mayHaveReachedProvider
  | _ => none

theorem dispatchBoundaryCanBeCrossedOnlyOnce (phase : NtzsAttemptPhase) :
    markNtzsDispatch phase = some .mayHaveReachedProvider ↔ phase = .prepared := by
  cases phase <;> simp [markNtzsDispatch]

def prepareNtzsRequest (existing incoming : Nat) : Option Nat :=
  if existing = incoming then some existing else none

theorem exactNtzsRequestReplayIsIdempotent (request : Nat) :
    prepareNtzsRequest request request = some request := by
  simp [prepareNtzsRequest]

theorem changedNtzsRequestIsRejected
    (existing incoming : Nat)
    (hChanged : existing ≠ incoming) :
    prepareNtzsRequest existing incoming = none := by
  simp [prepareNtzsRequest, hChanged]

def bindNtzsProviderReference
    (phase : NtzsAttemptPhase)
    (existing incoming : Nat) : Option (NtzsAttemptPhase × Nat) :=
  match phase with
  | .mayHaveReachedProvider => some (.providerReferenceBound, incoming)
  | .providerReferenceBound =>
      if existing = incoming then some (.providerReferenceBound, existing) else none
  | .prepared => none

theorem changedBoundProviderReferenceIsRejected
    (existing incoming : Nat)
    (hChanged : existing ≠ incoming) :
    bindNtzsProviderReference .providerReferenceBound existing incoming = none := by
  simp [bindNtzsProviderReference, hChanged]

end ActiveChain.Payments
