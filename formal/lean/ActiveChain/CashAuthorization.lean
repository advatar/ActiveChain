/-!
# ActiveChain cash authorization and replay model

This model fixes the state-machine obligations for admitting a native-cash
spend.  It deliberately represents the PQ signature verifier as the Boolean
observation `signatureVerified`; cryptographic unforgeability is an assumption
of the primitive, while every protocol binding around that primitive is
explicit here.

An accepted spend must bind the exact intent, chain, sender, nonce, validity
window, payment session, and input set.  Acceptance advances the nonce and
consumes the session and inputs in one state transition.  The model therefore
proves replay rejection without relying on a caller-supplied transition ID.
-/

namespace ActiveChain.CashAuthorization

noncomputable section

local instance (proposition : Prop) : Decidable proposition :=
  Classical.propDecidable proposition

/-- The complete public value authorized by a cash signature. -/
structure Intent where
  chainId : Nat
  sender : Nat
  recipient : Nat
  nonce : Nat
  inputs : List Nat
  feeReserve : Nat
  amount : Nat
  fee : Nat
  validUntil : Nat
  deriving BEq, DecidableEq, Repr

/-- Evidence supplied at admission. `committedIntent` stands for the exact
canonical signing transcript recovered by the verifier. -/
structure Witness where
  signer : Nat
  sessionId : Nat
  sessionExpires : Nat
  committedIntent : Intent
  signatureVerified : Bool
  deriving BEq, DecidableEq, Repr

/-- Durable admission state for one sender-local nonce lane. -/
structure State where
  chainId : Nat
  sender : Nat
  nextNonce : Nat
  consumedSessions : List Nat
  consumedInputs : List Nat
  deriving BEq, DecidableEq, Repr

/-- Every input, including the independent fee reserve, must still be live. -/
def InputsAvailable (state : State) (intent : Intent) : Prop :=
  (∀ input ∈ intent.inputs, input ∉ state.consumedInputs) ∧
    intent.feeReserve ∉ state.consumedInputs ∧
    intent.feeReserve ∉ intent.inputs

/-- Complete authorization predicate at the cash ingress boundary. -/
def AuthorizedAt
    (state : State) (intent : Intent) (witness : Witness) (height : Nat) : Prop :=
  intent.chainId = state.chainId ∧
    intent.sender = state.sender ∧
    witness.signer = intent.sender ∧
    witness.committedIntent = intent ∧
    witness.signatureVerified = true ∧
    intent.nonce = state.nextNonce ∧
    0 < intent.amount ∧
    height ≤ intent.validUntil ∧
    height ≤ witness.sessionExpires ∧
    witness.sessionId ∉ state.consumedSessions ∧
    InputsAvailable state intent

/-- Atomically advance the nonce and consume every replay-bearing resource. -/
def apply
    (state : State) (intent : Intent) (witness : Witness) (height : Nat) : Option State :=
  if AuthorizedAt state intent witness height then
    some {
      chainId := state.chainId
      sender := state.sender
      nextNonce := state.nextNonce + 1
      consumedSessions := witness.sessionId :: state.consumedSessions
      consumedInputs := intent.inputs ++ intent.feeReserve :: state.consumedInputs
    }
  else
    none

/-- Successful admission implies the complete authorization predicate. -/
theorem successImpliesAuthorization
    (pre post : State) (intent : Intent) (witness : Witness) (height : Nat)
    (accepted : apply pre intent witness height = some post) :
    AuthorizedAt pre intent witness height := by
  by_cases authorized : AuthorizedAt pre intent witness height
  · exact authorized
  · simp [apply, authorized] at accepted

/-- A signature over any different canonical intent is rejected. -/
theorem tamperedIntentRejected
    (state : State) (intent : Intent) (witness : Witness) (height : Nat)
    (tampered : witness.committedIntent ≠ intent) :
    apply state intent witness height = none := by
  have unauthorized : ¬ AuthorizedAt state intent witness height := by
    intro authorized
    rcases authorized with ⟨_, _, _, committed, _⟩
    exact tampered committed
  simp [apply, unauthorized]

/-- Cross-chain replay is rejected before state mutation. -/
theorem wrongChainRejected
    (state : State) (intent : Intent) (witness : Witness) (height : Nat)
    (wrongChain : intent.chainId ≠ state.chainId) :
    apply state intent witness height = none := by
  have unauthorized : ¬ AuthorizedAt state intent witness height := by
    intro authorized
    rcases authorized with ⟨chain, _⟩
    exact wrongChain chain
  simp [apply, unauthorized]

/-- A false PQ-verifier result can never reach the cash transition. -/
theorem invalidSignatureRejected
    (state : State) (intent : Intent) (witness : Witness) (height : Nat)
    (invalid : witness.signatureVerified = false) :
    apply state intent witness height = none := by
  have unauthorized : ¬ AuthorizedAt state intent witness height := by
    intro authorized
    rcases authorized with ⟨_, _, _, _, verified, _⟩
    simp [invalid] at verified
  simp [apply, unauthorized]

/-- Acceptance advances exactly one sender-local nonce. -/
theorem successAdvancesNonce
    (pre post : State) (intent : Intent) (witness : Witness) (height : Nat)
    (accepted : apply pre intent witness height = some post) :
    post.nextNonce = pre.nextNonce + 1 := by
  have authorized := successImpliesAuthorization pre post intent witness height accepted
  simp [apply, authorized] at accepted
  subst post
  rfl

/-- The accepted payment session is durably consumed. -/
theorem successConsumesSession
    (pre post : State) (intent : Intent) (witness : Witness) (height : Nat)
    (accepted : apply pre intent witness height = some post) :
    witness.sessionId ∈ post.consumedSessions := by
  have authorized := successImpliesAuthorization pre post intent witness height accepted
  simp [apply, authorized] at accepted
  subst post
  simp

/-- Every accepted input and the fee reserve are durably consumed. -/
theorem successConsumesInputs
    (pre post : State) (intent : Intent) (witness : Witness) (height : Nat)
    (accepted : apply pre intent witness height = some post) :
    (∀ input ∈ intent.inputs, input ∈ post.consumedInputs) ∧
      intent.feeReserve ∈ post.consumedInputs := by
  have authorized := successImpliesAuthorization pre post intent witness height accepted
  simp [apply, authorized] at accepted
  subst post
  constructor
  · intro input member
    exact List.mem_append_left _ member
  · simp

/-- Reusing an accepted payment session is impossible, even for another
otherwise-valid intent. -/
theorem sessionIsOneShot
    (pre post : State) (first second : Intent) (witness : Witness)
    (firstHeight secondHeight : Nat)
    (accepted : apply pre first witness firstHeight = some post) :
    apply post second witness secondHeight = none := by
  have consumed := successConsumesSession pre post first witness firstHeight accepted
  have unauthorized : ¬ AuthorizedAt post second witness secondHeight := by
    intro authorized
    rcases authorized with ⟨_, _, _, _, _, _, _, _, _, fresh, _⟩
    exact fresh consumed
  simp [apply, unauthorized]

/-- Replaying the exact spend is rejected by both the advanced nonce and the
consumed session/input barriers. -/
theorem acceptedSpendCannotReplay
    (pre post : State) (intent : Intent) (witness : Witness) (height replayHeight : Nat)
    (accepted : apply pre intent witness height = some post) :
    apply post intent witness replayHeight = none := by
  exact sessionIsOneShot pre post intent intent witness height replayHeight accepted

/-- No accepted transition changes the immutable chain or sender lane. -/
theorem successPreservesDomain
    (pre post : State) (intent : Intent) (witness : Witness) (height : Nat)
    (accepted : apply pre intent witness height = some post) :
    post.chainId = pre.chainId ∧ post.sender = pre.sender := by
  have authorized := successImpliesAuthorization pre post intent witness height accepted
  simp [apply, authorized] at accepted
  subst post
  exact ⟨rfl, rfl⟩

end

end ActiveChain.CashAuthorization
