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

end ActiveChain.Payments
