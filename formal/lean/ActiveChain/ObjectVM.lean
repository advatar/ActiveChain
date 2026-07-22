/-!
# ActiveChain P-050 ObjectVM resource and cost model

This executable model fixes the copy/move/consume resource algebra and the
version-1 costs independently of the Rust verifier and interpreter.
-/

namespace ActiveChain.ObjectVM

inductive ValueKind where
  | u64
  | bool
  | digest
  | object
  | capability
  deriving BEq, DecidableEq, Repr

def isCopyable : ValueKind → Bool
  | .u64 | .bool | .digest => true
  | .object | .capability => false

inductive Action where
  | copy
  | move
  | consume
  deriving BEq, DecidableEq, Repr

inductive Verdict where
  | accept
  | copyRequiresCopyable
  | typeMismatch
  deriving BEq, DecidableEq, Repr

/-- The local resource check performed before register-state checking. -/
def checkAction : Action → ValueKind → Verdict
  | .copy, kind => if isCopyable kind then .accept else .copyRequiresCopyable
  | .move, _ => .accept
  | .consume, .capability => .accept
  | .consume, _ => .typeMismatch

/-- All actions in the differential table have fixed version-1 cost one. -/
def actionGasCost (_ : Action) : Nat := 1

/-- Exact gas of an arbitrary straight-line sequence in the resource algebra. -/
def programGas (actions : List Action) : Nat :=
  (actions.map actionGasCost).sum

theorem programGasExact (actions : List Action) :
    programGas actions = actions.length := by
  induction actions with
  | nil => rfl
  | cons action actions ih =>
      unfold programGas at ih ⊢
      cases action <;> simp [actionGasCost, ih, Nat.add_comm]

/-- Production verifier certificate projected to runtime value presence. -/
structure InstructionCertificate where
  available : List Bool
  maximumPriorEvents : Nat
  deriving BEq, DecidableEq, Repr

/-- Pure verifier/interpreter refinement predicate used at every instruction. -/
def admitsRuntimeState
    (certificate : InstructionCertificate)
    (runtimeAvailable : List Bool)
    (priorEvents : Nat) : Bool :=
  decide (runtimeAvailable = certificate.available) &&
    decide (priorEvents ≤ certificate.maximumPriorEvents)

theorem admitsRuntimeStateIff
    (certificate : InstructionCertificate)
    (runtimeAvailable : List Bool)
    (priorEvents : Nat) :
    admitsRuntimeState certificate runtimeAvailable priorEvents = true ↔
      runtimeAvailable = certificate.available ∧
      priorEvents ≤ certificate.maximumPriorEvents := by
  simp [admitsRuntimeState]

@[simp] theorem exactCertificateAdmits
    (certificate : InstructionCertificate)
    (priorEvents : Nat)
    (bounded : priorEvents ≤ certificate.maximumPriorEvents) :
    admitsRuntimeState certificate certificate.available priorEvents = true := by
  simp [admitsRuntimeState, bounded]

@[simp] theorem objectCopyRejected :
    checkAction .copy .object = .copyRequiresCopyable := rfl

@[simp] theorem capabilityCopyRejected :
    checkAction .copy .capability = .copyRequiresCopyable := rfl

@[simp] theorem capabilityConsumptionAccepted :
    checkAction .consume .capability = .accept := rfl

theorem moveAcceptsEveryKind (kind : ValueKind) :
    checkAction .move kind = .accept := by
  cases kind <;> rfl

/-- Availability of a source/destination pair before and after one move. -/
def moveAvailability : Bool × Bool → Option (Bool × Bool)
  | (true, false) => some (false, true)
  | _ => none

def liveCount (state : Bool × Bool) : Nat :=
  (if state.1 then 1 else 0) + (if state.2 then 1 else 0)

@[simp] theorem movePreservesOneLiveValue :
    liveCount (false, true) = liveCount (true, false) := rfl

def modelCases : List (Action × ValueKind) :=
  [
    (.copy, .u64),
    (.copy, .capability),
    (.copy, .object),
    (.consume, .capability),
    (.consume, .object),
    (.move, .object)
  ]

def modelTable : List (Action × ValueKind × Verdict × Nat) :=
  modelCases.map fun (action, kind) =>
    (action, kind, checkAction action kind, actionGasCost action)

theorem modelTableHasSixRows : modelTable.length = 6 := rfl

end ActiveChain.ObjectVM
