/-!
# ActiveChain OpenWallet consent-bound issuance and disclosure model

This executable model covers the OpenWallet adapter transition system shared by credential issuance
and presentation: an offer may only enter the adapter in the `offered` state, only
`authorizeIssuance` may move it to `authorized`, and only an `authorized` offer may complete. It
also covers grant-nonce one-shotness and the disclosure-versus-request binding enforced when a
presentation consent is approved.

Canonical decoding, cryptographic issuer authentication, credential-content validity, and digest
collision resistance are explicit production-boundary assumptions: identifiers, nonces, consent
digests, and request commitments are modeled as opaque `Nat` tokens compared for equality.
-/

namespace ActiveChain.OpenWalletConsent

/-- Mirrors `MAX_OPENWALLET_CREDENTIALS`. -/
def maxCredentials : Nat := 256

/-- Mirrors `MAX_OPENWALLET_SESSIONS`. -/
def maxSessions : Nat := 64

inductive IssuanceState where
  | offered
  | authorized
  | completed
  deriving BEq, DecidableEq, Inhabited, Repr

structure Session where
  id : Nat
  relyingParty : Nat
  expiresAt : Nat
  deriving BEq, DecidableEq, Inhabited, Repr

structure CredentialRef where
  credentialId : Nat
  schemaId : Nat
  issuer : Nat
  deriving BEq, DecidableEq, Inhabited, Repr

/-- The abstract projection of `OpenWalletCredentialOfferV1`: the issuance session, the grant nonce
that gates completion, the consent digest that gates authorization, and the wire-restored state. -/
structure Offer where
  session : Session
  grantNonce : Nat
  consentDigest : Nat
  state : IssuanceState
  deriving BEq, DecidableEq, Inhabited, Repr

/-- The abstract projection of `OpenWalletPresentationRequestV1`: `commitment` stands for the
canonical commitment a consent must reproduce, and `requested` for the requested schema set. -/
structure Request where
  session : Session
  nonce : Nat
  commitment : Nat
  requested : List Nat
  deriving BEq, DecidableEq, Inhabited, Repr

/-- The abstract projection of `OpenWalletConsentV1`. The approval height participates only in
constructor well-formedness, which the model treats as an input precondition. -/
structure Consent where
  sessionId : Nat
  requestCommitment : Nat
  selected : List Nat
  expiresAt : Nat
  deriving BEq, DecidableEq, Inhabited, Repr

structure Adapter where
  sessions : List Session
  credentials : List CredentialRef
  issuance : List Offer
  presentations : List Request
  consumedNonces : List Nat
  deriving BEq, DecidableEq, Inhabited, Repr

def empty : Adapter :=
  { sessions := [], credentials := [], issuance := [], presentations := [], consumedNonces := [] }

def lookupCredential (a : Adapter) (credentialId : Nat) : Option CredentialRef :=
  a.credentials.find? (fun item => item.credentialId == credentialId)

def lookupSession (a : Adapter) (sessionId : Nat) : Option Session :=
  a.sessions.find? (fun item => item.id == sessionId)

def lookupOffer (a : Adapter) (sessionId : Nat) : Option Offer :=
  a.issuance.find? (fun item => item.session.id == sessionId)

def lookupRequest (a : Adapter) (sessionId : Nat) : Option Request :=
  a.presentations.find? (fun item => item.session.id == sessionId)

/-- The issuance state rewrite performed by `authorize_issuance` and `complete_issuance`: only the
addressed session's state changes, every other field and every other offer is untouched. -/
def setOfferState (a : Adapter) (sessionId : Nat) (state : IssuanceState) : Adapter :=
  { a with
    issuance :=
      a.issuance.map (fun item => if item.session.id = sessionId then { item with state } else item) }

/-- Registration rejects zero identifiers, a full table, and duplicate credential identifiers. -/
def registerCredential (a : Adapter) (credential : CredentialRef) : Option Adapter :=
  if credential.credentialId = 0 ∨ credential.schemaId = 0 ∨ credential.issuer = 0 ∨
      maxCredentials ≤ a.credentials.length ∨
      (lookupCredential a credential.credentialId).isSome then
    none
  else
    some { a with credentials := a.credentials ++ [credential] }

/-- Session admission rejects zero identifiers, an already expired session, a full table, and a
reused session identifier. -/
def openSession (a : Adapter) (session : Session) (height : Nat) : Option Adapter :=
  if session.id = 0 ∨ session.relyingParty = 0 ∨ session.expiresAt = 0 ∨
      session.expiresAt < height ∨ maxSessions ≤ a.sessions.length ∨
      (lookupSession a session.id).isSome then
    none
  else
    some { a with sessions := a.sessions ++ [session] }

/-- Offer admission. The first disjunct is the #678 fix: an offer whose decoded state is anything
other than `offered` is refused outright, so it can never reach `completeIssuance` without passing
`authorizeIssuance`. -/
def beginIssuance (a : Adapter) (offer : Offer) (height : Nat) : Option Adapter :=
  if offer.state ≠ IssuanceState.offered ∨ offer.session.expiresAt < height ∨
      offer.grantNonce ∈ a.consumedNonces ∨ (lookupOffer a offer.session.id).isSome then
    none
  else
    match openSession a offer.session height with
    | none => none
    | some opened => some { opened with issuance := opened.issuance ++ [offer] }

/-- The only transition that produces `authorized`. It requires the offer to still be `offered` and
the supplied consent digest to equal the offer's. -/
def authorizeIssuance (a : Adapter) (sessionId consentDigest height : Nat) : Option Adapter :=
  match lookupOffer a sessionId with
  | none => none
  | some offer =>
    if offer.state ≠ IssuanceState.offered ∨ offer.consentDigest ≠ consentDigest ∨
        offer.session.expiresAt < height then
      none
    else
      some (setOfferState a sessionId IssuanceState.authorized)

/-- Completion requires an `authorized` offer, the matching grant nonce, an unexpired session, and
an unconsumed nonce. It registers the credential and consumes the nonce. -/
def completeIssuance (a : Adapter) (sessionId : Nat) (credential : CredentialRef)
    (grantNonce height : Nat) : Option Adapter :=
  match lookupOffer a sessionId with
  | none => none
  | some offer =>
    if offer.state ≠ IssuanceState.authorized ∨ offer.grantNonce ≠ grantNonce ∨
        offer.session.expiresAt < height ∨ grantNonce ∈ a.consumedNonces then
      none
    else
      match registerCredential a credential with
      | none => none
      | some registered =>
        some
          { setOfferState registered sessionId IssuanceState.completed with
            consumedNonces := registered.consumedNonces ++ [grantNonce] }

def beginPresentation (a : Adapter) (request : Request) (height : Nat) : Option Adapter :=
  if request.session.expiresAt < height ∨ request.nonce ∈ a.consumedNonces ∨
      (lookupRequest a request.session.id).isSome then
    none
  else
    match openSession a request.session height with
    | none => none
    | some opened => some { opened with presentations := opened.presentations ++ [request] }

/-- Resolve every selected credential to the schema the wallet holds for it, failing closed on the
first identifier the wallet does not hold. -/
def disclosedSchemas (a : Adapter) : List Nat → Option (List Nat)
  | [] => some []
  | credentialId :: rest =>
    match lookupCredential a credentialId, disclosedSchemas a rest with
    | some credential, some tail => some (credential.schemaId :: tail)
    | _, _ => none

/-- Approval requires the consent to reproduce the request commitment, an unexpired consent and
session, an unconsumed request nonce, every selected credential to be held, every disclosed schema
to answer a requested schema (no over-disclosure), and every requested schema to be answered. -/
def approvePresentation (a : Adapter) (consent : Consent) (height : Nat) : Option Adapter :=
  match lookupRequest a consent.sessionId with
  | none => none
  | some request =>
    if consent.expiresAt < height ∨ request.session.expiresAt < height ∨
        consent.requestCommitment ≠ request.commitment ∨ request.nonce ∈ a.consumedNonces then
      none
    else
      match disclosedSchemas a consent.selected with
      | none => none
      | some disclosed =>
        if (∀ held ∈ disclosed, held ∈ request.requested) ∧
            (∀ want ∈ request.requested, want ∈ disclosed) then
          some { a with consumedNonces := a.consumedNonces ++ [request.nonce] }
        else
          none

inductive Step where
  | registerCredential (credential : CredentialRef)
  | openSession (session : Session) (height : Nat)
  | beginIssuance (offer : Offer) (height : Nat)
  | authorizeIssuance (sessionId consentDigest height : Nat)
  | completeIssuance (sessionId : Nat) (credential : CredentialRef) (grantNonce height : Nat)
  | beginPresentation (request : Request) (height : Nat)
  | approvePresentation (consent : Consent) (height : Nat)
  deriving DecidableEq, Inhabited, Repr

def step (a : Adapter) : Step → Option Adapter
  | .registerCredential credential => registerCredential a credential
  | .openSession session height => openSession a session height
  | .beginIssuance offer height => beginIssuance a offer height
  | .authorizeIssuance sessionId consentDigest height =>
    authorizeIssuance a sessionId consentDigest height
  | .completeIssuance sessionId credential grantNonce height =>
    completeIssuance a sessionId credential grantNonce height
  | .beginPresentation request height => beginPresentation a request height
  | .approvePresentation consent height => approvePresentation a consent height

/-- The state transition a wallet performs for an attempted step: a rejected attempt is a no-op. -/
def applyStep (a : Adapter) (s : Step) : Adapter := (step a s).getD a

def runFrom (a : Adapter) : List Step → Adapter
  | [] => a
  | s :: rest => runFrom (applyStep a s) rest

/-- Every reachable adapter state is `run trace` for some trace of attempted steps. -/
def run (trace : List Step) : Adapter := runFrom empty trace

def stateCount (a : Adapter) (state : IssuanceState) : Nat :=
  (a.issuance.filter (fun item => item.state == state)).length

/-! ## List plumbing -/

private theorem findAppendSingleton {α : Type} (l : List α) (x : α) (p : α → Bool) :
    (l ++ [x]).find? p =
      match l.find? p with
      | some found => some found
      | none => if p x then some x else none := by
  induction l with
  | nil => simp [List.find?]
  | cons head tail ih =>
    by_cases h : p head
    · simp [h]
    · simp [h, ih]

private theorem findMapKey (l : List Offer) (f : Offer → Offer)
    (key : ∀ item, (f item).session.id = item.session.id) (sessionId : Nat) :
    (l.map f).find? (fun item => item.session.id == sessionId) =
      (l.find? (fun item => item.session.id == sessionId)).map f := by
  induction l with
  | nil => rfl
  | cons head tail ih =>
    by_cases h : head.session.id = sessionId
    · simp [key head, h]
    · simp [key head, h, ih]

private theorem findKeyEq (l : List Offer) (sessionId : Nat) (offer : Offer)
    (found : l.find? (fun item => item.session.id == sessionId) = some offer) :
    offer.session.id = sessionId := by
  induction l with
  | nil => simp at found
  | cons head tail ih =>
    by_cases h : head.session.id = sessionId
    · simp [h] at found
      simp [← found, h]
    · simp [h] at found
      exact ih found

theorem lookupOfferKeyEq (a : Adapter) (sessionId : Nat) (offer : Offer)
    (found : lookupOffer a sessionId = some offer) : offer.session.id = sessionId :=
  findKeyEq a.issuance sessionId offer found

/-! ## Per-transition issuance projections -/

theorem lookupOfferOfIssuanceEq {a b : Adapter} (h : b.issuance = a.issuance) (sessionId : Nat) :
    lookupOffer b sessionId = lookupOffer a sessionId := by
  simp [lookupOffer, h]

theorem registerCredentialIssuance {a post : Adapter} {credential : CredentialRef}
    (accepted : registerCredential a credential = some post) : post.issuance = a.issuance := by
  unfold registerCredential at accepted
  split at accepted
  · exact absurd accepted (by simp)
  · rw [← Option.some.inj accepted]

theorem registerCredentialConsumedNonces {a post : Adapter} {credential : CredentialRef}
    (accepted : registerCredential a credential = some post) :
    post.consumedNonces = a.consumedNonces := by
  unfold registerCredential at accepted
  split at accepted
  · exact absurd accepted (by simp)
  · rw [← Option.some.inj accepted]

theorem openSessionIssuance {a post : Adapter} {session : Session} {height : Nat}
    (accepted : openSession a session height = some post) : post.issuance = a.issuance := by
  unfold openSession at accepted
  split at accepted
  · exact absurd accepted (by simp)
  · rw [← Option.some.inj accepted]

theorem openSessionConsumedNonces {a post : Adapter} {session : Session} {height : Nat}
    (accepted : openSession a session height = some post) :
    post.consumedNonces = a.consumedNonces := by
  unfold openSession at accepted
  split at accepted
  · exact absurd accepted (by simp)
  · rw [← Option.some.inj accepted]

theorem beginIssuanceIssuance {a post : Adapter} {offer : Offer} {height : Nat}
    (accepted : beginIssuance a offer height = some post) :
    post.issuance = a.issuance ++ [offer] ∧ offer.state = IssuanceState.offered := by
  unfold beginIssuance at accepted
  split at accepted
  case isTrue => exact absurd accepted (by simp)
  case isFalse guard =>
    simp only [not_or, ne_eq, Classical.not_not] at guard
    split at accepted
    case h_1 => exact absurd accepted (by simp)
    case h_2 opened opening =>
      rw [← Option.some.inj accepted]
      exact ⟨by simp [openSessionIssuance opening], guard.1⟩

theorem beginIssuanceConsumedNonces {a post : Adapter} {offer : Offer} {height : Nat}
    (accepted : beginIssuance a offer height = some post) :
    post.consumedNonces = a.consumedNonces := by
  unfold beginIssuance at accepted
  split at accepted
  · exact absurd accepted (by simp)
  · split at accepted
    · exact absurd accepted (by simp)
    case h_2 opened opening =>
      rw [← Option.some.inj accepted]
      simp [openSessionConsumedNonces opening]

theorem beginPresentationIssuance {a post : Adapter} {request : Request} {height : Nat}
    (accepted : beginPresentation a request height = some post) : post.issuance = a.issuance := by
  unfold beginPresentation at accepted
  split at accepted
  · exact absurd accepted (by simp)
  · split at accepted
    · exact absurd accepted (by simp)
    case h_2 opened opening =>
      rw [← Option.some.inj accepted]
      simp [openSessionIssuance opening]

theorem beginPresentationConsumedNonces {a post : Adapter} {request : Request} {height : Nat}
    (accepted : beginPresentation a request height = some post) :
    post.consumedNonces = a.consumedNonces := by
  unfold beginPresentation at accepted
  split at accepted
  · exact absurd accepted (by simp)
  · split at accepted
    · exact absurd accepted (by simp)
    case h_2 opened opening =>
      rw [← Option.some.inj accepted]
      simp [openSessionConsumedNonces opening]

theorem lookupOfferSetOfferState (a : Adapter) (target sessionId : Nat) (state : IssuanceState) :
    lookupOffer (setOfferState a target state) sessionId =
      (lookupOffer a sessionId).map
        (fun item => if item.session.id = target then { item with state } else item) := by
  simp only [lookupOffer, setOfferState]
  exact findMapKey a.issuance _ (by intro item; by_cases h : item.session.id = target <;> simp [h])
    sessionId

theorem lookupOfferSetOfferStateSame {a : Adapter} {target : Nat} {state : IssuanceState}
    {offer : Offer} (found : lookupOffer a target = some offer) :
    lookupOffer (setOfferState a target state) target = some { offer with state } := by
  rw [lookupOfferSetOfferState, found]
  simp [lookupOfferKeyEq a target offer found]

theorem lookupOfferSetOfferStateOther (a : Adapter) {target sessionId : Nat}
    {state : IssuanceState} (distinct : sessionId ≠ target) :
    lookupOffer (setOfferState a target state) sessionId = lookupOffer a sessionId := by
  rw [lookupOfferSetOfferState]
  cases found : lookupOffer a sessionId with
  | none => rfl
  | some offer =>
    have key := lookupOfferKeyEq a sessionId offer found
    simp [key, distinct]

theorem completeIssuanceIssuance {a post : Adapter} {sessionId : Nat} {credential : CredentialRef}
    {grantNonce height : Nat}
    (accepted : completeIssuance a sessionId credential grantNonce height = some post) :
    post.issuance = (setOfferState a sessionId IssuanceState.completed).issuance := by
  unfold completeIssuance at accepted
  split at accepted
  · exact absurd accepted (by simp)
  · split at accepted
    · exact absurd accepted (by simp)
    · split at accepted
      · exact absurd accepted (by simp)
      case h_2 registered registration =>
        rw [← Option.some.inj accepted]
        simp [setOfferState, registerCredentialIssuance registration]

/-! ## Consent-bound issuance -/

/-- Completion requires the addressed session to already be `authorized` with the matching grant
nonce. -/
theorem completionRequiresAuthorized {a post : Adapter} {sessionId : Nat}
    {credential : CredentialRef} {grantNonce height : Nat}
    (accepted : completeIssuance a sessionId credential grantNonce height = some post) :
    ∃ offer, lookupOffer a sessionId = some offer ∧
      offer.state = IssuanceState.authorized ∧ offer.grantNonce = grantNonce := by
  unfold completeIssuance at accepted
  split at accepted
  case h_1 => exact absurd accepted (by simp)
  case h_2 offer found =>
    split at accepted
    case isTrue => exact absurd accepted (by simp)
    case isFalse guard =>
      simp only [not_or, ne_eq, Classical.not_not] at guard
      exact ⟨offer, found, guard.1, guard.2.1⟩

/-- Authorization requires the addressed session to still be `offered` and the supplied consent
digest to equal the offer's. This is the only step that inspects the consent digest at all. -/
theorem authorizationRequiresMatchingConsent {a post : Adapter} {sessionId consentDigest height : Nat}
    (accepted : authorizeIssuance a sessionId consentDigest height = some post) :
    ∃ offer, lookupOffer a sessionId = some offer ∧
      offer.state = IssuanceState.offered ∧ offer.consentDigest = consentDigest ∧
      post = setOfferState a sessionId IssuanceState.authorized := by
  unfold authorizeIssuance at accepted
  split at accepted
  case h_1 => exact absurd accepted (by simp)
  case h_2 offer found =>
    split at accepted
    case isTrue => exact absurd accepted (by simp)
    case isFalse guard =>
      simp only [not_or, ne_eq, Classical.not_not] at guard
      exact ⟨offer, found, guard.1, guard.2.1, (Option.some.inj accepted).symm⟩

/-- Theorem 2 (regression for #678): an offer presented with any state other than `offered` is
rejected by `beginIssuance`, and the attempted step leaves the adapter unchanged. -/
theorem preAuthorizedOffersAreRejected (a : Adapter) (offer : Offer) (height : Nat)
    (notOffered : offer.state ≠ IssuanceState.offered) :
    beginIssuance a offer height = none ∧
      applyStep a (Step.beginIssuance offer height) = a := by
  have rejected : beginIssuance a offer height = none := by
    unfold beginIssuance
    split
    case isTrue => rfl
    case isFalse guard => exact absurd (Or.inl notOffered) guard
  exact ⟨rejected, by simp [applyStep, step, rejected]⟩

/-- No transition other than `authorizeIssuance` for the very same session and consent digest can
leave a session in the `authorized` state. -/
def authorizedWith (a : Adapter) (sessionId consentDigest : Nat) : Prop :=
  ∃ offer, lookupOffer a sessionId = some offer ∧
    offer.state = IssuanceState.authorized ∧ offer.consentDigest = consentDigest

/-- The trace contains an authorization step for this session carrying this consent digest. -/
def consentedIn (trace : List Step) (sessionId consentDigest : Nat) : Prop :=
  ∃ height, Step.authorizeIssuance sessionId consentDigest height ∈ trace

private theorem authorizedWithOfIssuanceEq {a b : Adapter} (h : b.issuance = a.issuance)
    {sessionId consentDigest : Nat} (auth : authorizedWith b sessionId consentDigest) :
    authorizedWith a sessionId consentDigest := by
  obtain ⟨offer, found, state, digest⟩ := auth
  exact ⟨offer, by rw [← lookupOfferOfIssuanceEq h sessionId]; exact found, state, digest⟩

/-- The single-step core of the headline theorem: the only way a step can leave a session in the
`authorized` state carrying a consent digest is for that step to be the authorization of that very
session with that very digest, or for the session to have already been authorized. -/
theorem authorizedStepIsAuthorization (a : Adapter) (s : Step) (sessionId consentDigest : Nat)
    (auth : authorizedWith (applyStep a s) sessionId consentDigest) :
    (∃ height, s = Step.authorizeIssuance sessionId consentDigest height) ∨
      authorizedWith a sessionId consentDigest := by
  cases s with
  | registerCredential credential =>
    refine Or.inr ?_
    cases outcome : registerCredential a credential with
    | none => simpa [applyStep, step, outcome] using auth
    | some post =>
      rw [applyStep, step, outcome, Option.getD_some] at auth
      exact authorizedWithOfIssuanceEq (registerCredentialIssuance outcome) auth
  | openSession session height =>
    refine Or.inr ?_
    cases outcome : openSession a session height with
    | none => simpa [applyStep, step, outcome] using auth
    | some post =>
      rw [applyStep, step, outcome, Option.getD_some] at auth
      exact authorizedWithOfIssuanceEq (openSessionIssuance outcome) auth
  | beginPresentation request height =>
    refine Or.inr ?_
    cases outcome : beginPresentation a request height with
    | none => simpa [applyStep, step, outcome] using auth
    | some post =>
      rw [applyStep, step, outcome, Option.getD_some] at auth
      exact authorizedWithOfIssuanceEq (beginPresentationIssuance outcome) auth
  | approvePresentation consent height =>
    refine Or.inr ?_
    cases outcome : approvePresentation a consent height with
    | none => simpa [applyStep, step, outcome] using auth
    | some post =>
      have issuanceEq : post.issuance = a.issuance := by
        unfold approvePresentation at outcome
        split at outcome
        · exact absurd outcome (by simp)
        · split at outcome
          · exact absurd outcome (by simp)
          · split at outcome
            · exact absurd outcome (by simp)
            · split at outcome
              · rw [← Option.some.inj outcome]
              · exact absurd outcome (by simp)
      rw [applyStep, step, outcome, Option.getD_some] at auth
      exact authorizedWithOfIssuanceEq issuanceEq auth
  | beginIssuance offer height =>
    refine Or.inr ?_
    cases outcome : beginIssuance a offer height with
    | none => simpa [applyStep, step, outcome] using auth
    | some post =>
      obtain ⟨issuanceEq, offered⟩ := beginIssuanceIssuance outcome
      rw [applyStep, step, outcome, Option.getD_some] at auth
      obtain ⟨found, foundEq, state, digest⟩ := auth
      have resolved := findAppendSingleton a.issuance offer
        (fun item => item.session.id == sessionId)
      simp only [lookupOffer, issuanceEq, resolved] at foundEq
      cases prior : a.issuance.find? (fun item => item.session.id == sessionId) with
      | some existing =>
        rw [prior] at foundEq
        exact ⟨found, by simpa [lookupOffer] using foundEq ▸ prior, state, digest⟩
      | none =>
        rw [prior] at foundEq
        simp only at foundEq
        split at foundEq
        · rw [← Option.some.inj foundEq] at state
          exact absurd (offered ▸ state) (by simp)
        · exact absurd foundEq (by simp)
  | completeIssuance target credential grantNonce height =>
    refine Or.inr ?_
    cases outcome : completeIssuance a target credential grantNonce height with
    | none => simpa [applyStep, step, outcome] using auth
    | some post =>
      have issuanceEq := completeIssuanceIssuance outcome
      rw [applyStep, step, outcome, Option.getD_some] at auth
      obtain ⟨found, foundEq, state, digest⟩ := auth
      rw [lookupOfferOfIssuanceEq issuanceEq sessionId] at foundEq
      by_cases same : sessionId = target
      · subst same
        obtain ⟨offer, prior, _, _⟩ := completionRequiresAuthorized outcome
        rw [lookupOfferSetOfferStateSame prior] at foundEq
        rw [← Option.some.inj foundEq] at state
        exact absurd state (by simp)
      · rw [lookupOfferSetOfferStateOther a same] at foundEq
        exact ⟨found, foundEq, state, digest⟩
  | authorizeIssuance target digest height =>
    cases outcome : authorizeIssuance a target digest height with
    | none =>
      refine Or.inr ?_
      simpa [applyStep, step, outcome] using auth
    | some post =>
      obtain ⟨offer, prior, offered, digestEq, postEq⟩ :=
        authorizationRequiresMatchingConsent outcome
      rw [applyStep, step, outcome, Option.getD_some] at auth
      obtain ⟨found, foundEq, state, foundDigest⟩ := auth
      subst postEq
      by_cases same : sessionId = target
      · subst same
        rw [lookupOfferSetOfferStateSame prior] at foundEq
        rw [← Option.some.inj foundEq] at foundDigest
        exact Or.inl ⟨height, by rw [← digestEq, ← foundDigest]⟩
      · refine Or.inr ?_
        rw [lookupOfferSetOfferStateOther a same] at foundEq
        exact ⟨found, foundEq, state, foundDigest⟩

private theorem runFromCons (a : Adapter) (s : Step) (rest : List Step) :
    runFrom a (s :: rest) = runFrom (applyStep a s) rest := rfl

/-- Every authorized session in a state reached from `a` was either already authorized in `a` or was
authorized by an explicit `authorizeIssuance` step carrying exactly its consent digest. -/
theorem authorizedRequiresConsentFrom (a : Adapter) (trace : List Step)
    (sessionId consentDigest : Nat)
    (auth : authorizedWith (runFrom a trace) sessionId consentDigest) :
    consentedIn trace sessionId consentDigest ∨ authorizedWith a sessionId consentDigest := by
  induction trace generalizing a with
  | nil => exact Or.inr auth
  | cons s rest ih =>
    rw [runFromCons] at auth
    rcases ih (applyStep a s) auth with tail | here
    · exact Or.inl ⟨tail.choose, List.mem_cons_of_mem s tail.choose_spec⟩
    · rcases authorizedStepIsAuthorization a s sessionId consentDigest here with ⟨height, rfl⟩ | prior
      · exact Or.inl ⟨height, List.mem_cons_self ..⟩
      · exact Or.inr prior

theorem emptyIsNeverAuthorized (sessionId consentDigest : Nat) :
    ¬ authorizedWith empty sessionId consentDigest := by
  rintro ⟨offer, found, -, -⟩
  simp [lookupOffer, empty] at found

theorem authorizedRequiresConsent (trace : List Step) (sessionId consentDigest : Nat)
    (auth : authorizedWith (run trace) sessionId consentDigest) :
    consentedIn trace sessionId consentDigest := by
  rcases authorizedRequiresConsentFrom empty trace sessionId consentDigest auth with h | h
  · exact h
  · exact absurd h (emptyIsNeverAuthorized sessionId consentDigest)

/-- Theorem 1 (headline): in any reachable adapter state, an accepted `completeIssuance` implies the
session is `authorized`, and the only way it became `authorized` is an explicit `authorizeIssuance`
step in the trace that supplied exactly the offer's consent digest. A credential can therefore never
be registered by an issuance that skipped the consent check. -/
theorem issuanceRequiresConsent (trace : List Step) (sessionId : Nat) (credential : CredentialRef)
    (grantNonce height : Nat) (post : Adapter)
    (accepted : completeIssuance (run trace) sessionId credential grantNonce height = some post) :
    ∃ offer, lookupOffer (run trace) sessionId = some offer ∧
      offer.state = IssuanceState.authorized ∧
      offer.grantNonce = grantNonce ∧
      consentedIn trace sessionId offer.consentDigest := by
  obtain ⟨offer, found, state, nonce⟩ := completionRequiresAuthorized accepted
  exact ⟨offer, found, state, nonce,
    authorizedRequiresConsent trace sessionId offer.consentDigest ⟨offer, found, state, rfl⟩⟩

/-! ## Grant-nonce one-shotness -/

theorem completedGrantNonceIsConsumed {a post : Adapter} {sessionId : Nat}
    {credential : CredentialRef} {grantNonce height : Nat}
    (accepted : completeIssuance a sessionId credential grantNonce height = some post) :
    grantNonce ∈ post.consumedNonces := by
  unfold completeIssuance at accepted
  split at accepted
  · exact absurd accepted (by simp)
  · split at accepted
    · exact absurd accepted (by simp)
    · split at accepted
      · exact absurd accepted (by simp)
      case h_2 registered registration =>
        rw [← Option.some.inj accepted]
        simp

theorem stepPreservesConsumedNonces (a : Adapter) (s : Step) (nonce : Nat)
    (present : nonce ∈ a.consumedNonces) : nonce ∈ (applyStep a s).consumedNonces := by
  cases s with
  | registerCredential credential =>
    cases outcome : registerCredential a credential with
    | none => simpa [applyStep, step, outcome] using present
    | some post =>
      rw [applyStep, step, outcome, Option.getD_some]
      simpa [registerCredentialConsumedNonces outcome] using present
  | openSession session height =>
    cases outcome : openSession a session height with
    | none => simpa [applyStep, step, outcome] using present
    | some post =>
      rw [applyStep, step, outcome, Option.getD_some]
      simpa [openSessionConsumedNonces outcome] using present
  | beginIssuance offer height =>
    cases outcome : beginIssuance a offer height with
    | none => simpa [applyStep, step, outcome] using present
    | some post =>
      rw [applyStep, step, outcome, Option.getD_some]
      simpa [beginIssuanceConsumedNonces outcome] using present
  | beginPresentation request height =>
    cases outcome : beginPresentation a request height with
    | none => simpa [applyStep, step, outcome] using present
    | some post =>
      rw [applyStep, step, outcome, Option.getD_some]
      simpa [beginPresentationConsumedNonces outcome] using present
  | authorizeIssuance target digest height =>
    cases outcome : authorizeIssuance a target digest height with
    | none => simpa [applyStep, step, outcome] using present
    | some post =>
      obtain ⟨-, -, -, -, postEq⟩ := authorizationRequiresMatchingConsent outcome
      rw [applyStep, step, outcome, Option.getD_some, postEq]
      simpa [setOfferState] using present
  | completeIssuance target credential grantNonce height =>
    cases outcome : completeIssuance a target credential grantNonce height with
    | none => simpa [applyStep, step, outcome] using present
    | some post =>
      have consumedEq : post.consumedNonces = a.consumedNonces ++ [grantNonce] := by
        unfold completeIssuance at outcome
        split at outcome
        · exact absurd outcome (by simp)
        · split at outcome
          · exact absurd outcome (by simp)
          · split at outcome
            · exact absurd outcome (by simp)
            case h_2 registered registration =>
              rw [← Option.some.inj outcome]
              simp [registerCredentialConsumedNonces registration]
      rw [applyStep, step, outcome, Option.getD_some, consumedEq]
      exact List.mem_append_left _ present
  | approvePresentation consent height =>
    cases outcome : approvePresentation a consent height with
    | none => simpa [applyStep, step, outcome] using present
    | some post =>
      have consumedSuper : ∃ nonces, post.consumedNonces = a.consumedNonces ++ nonces := by
        unfold approvePresentation at outcome
        split at outcome
        · exact absurd outcome (by simp)
        case h_2 request _ =>
          split at outcome
          · exact absurd outcome (by simp)
          · split at outcome
            · exact absurd outcome (by simp)
            · split at outcome
              · exact ⟨[request.nonce], by rw [← Option.some.inj outcome]⟩
              · exact absurd outcome (by simp)
      obtain ⟨nonces, consumedEq⟩ := consumedSuper
      rw [applyStep, step, outcome, Option.getD_some, consumedEq]
      exact List.mem_append_left _ present

theorem runFromPreservesConsumedNonces (a : Adapter) (trace : List Step) (nonce : Nat)
    (present : nonce ∈ a.consumedNonces) : nonce ∈ (runFrom a trace).consumedNonces := by
  induction trace generalizing a with
  | nil => exact present
  | cons s rest ih => exact ih (applyStep a s) (stepPreservesConsumedNonces a s nonce present)

theorem consumedGrantNonceIsRejected (a : Adapter) (nonce : Nat)
    (spent : nonce ∈ a.consumedNonces) :
    (∀ sessionId credential height,
        completeIssuance a sessionId credential nonce height = none) ∧
      (∀ offer height, offer.grantNonce = nonce → beginIssuance a offer height = none) := by
  constructor
  · intro sessionId credential height
    unfold completeIssuance
    split
    case h_1 => rfl
    case h_2 =>
      split
      case isTrue => rfl
      case isFalse guard =>
        simp only [not_or, ne_eq, Classical.not_not] at guard
        exact absurd spent guard.2.2.2
  · intro offer height replays
    unfold beginIssuance
    split
    case isTrue => rfl
    case isFalse guard =>
      simp only [not_or, ne_eq, Classical.not_not] at guard
      exact absurd (replays ▸ spent) guard.2.2.1

/-- Theorem 3: a completed issuance's grant nonce is one-shot. It is recorded as consumed, the
record survives every subsequent step, and every later state refuses both a second completion with
that nonce and any fresh offer that replays it. -/
theorem grantNonceIsOneShot {a post : Adapter} {sessionId : Nat} {credential : CredentialRef}
    {grantNonce height : Nat}
    (accepted : completeIssuance a sessionId credential grantNonce height = some post) :
    grantNonce ∈ post.consumedNonces ∧
      ∀ trace : List Step,
        (∀ laterSession laterCredential laterHeight,
            completeIssuance (runFrom post trace) laterSession laterCredential grantNonce
              laterHeight = none) ∧
          (∀ offer laterHeight, offer.grantNonce = grantNonce →
            beginIssuance (runFrom post trace) offer laterHeight = none) := by
  have consumed := completedGrantNonceIsConsumed accepted
  refine ⟨consumed, fun trace => ?_⟩
  exact consumedGrantNonceIsRejected (runFrom post trace) grantNonce
    (runFromPreservesConsumedNonces post trace grantNonce consumed)

/-! ## Disclosure binding -/

theorem disclosedSchemasAreHeld (a : Adapter) :
    ∀ (selected : List Nat) (disclosed : List Nat),
      disclosedSchemas a selected = some disclosed →
        (∀ credentialId ∈ selected, (lookupCredential a credentialId).isSome) ∧
          disclosed.length = selected.length
  | [], disclosed, resolved => by
    simp only [disclosedSchemas] at resolved
    rw [← Option.some.inj resolved]
    exact ⟨by simp, rfl⟩
  | credentialId :: rest, disclosed, resolved => by
    simp only [disclosedSchemas] at resolved
    split at resolved
    case h_1 credential tail held tailResolved =>
      obtain ⟨heldRest, lengthRest⟩ := disclosedSchemasAreHeld a rest tail tailResolved
      rw [← Option.some.inj resolved]
      refine ⟨?_, by simp [lengthRest]⟩
      intro item member
      rcases List.mem_cons.mp member with rfl | inRest
      · simp [held]
      · exact heldRest item inRest
    case h_2 => exact absurd resolved (by simp)

/-- Theorem 4: an accepted presentation approval exactly covers the request. Every selected
credential is held, every disclosed schema answers a requested schema (no over-disclosure), every
requested schema is answered, and the consent reproduced the request commitment. -/
theorem disclosureAnswersTheRequest {a post : Adapter} {consent : Consent} {height : Nat}
    (accepted : approvePresentation a consent height = some post) :
    ∃ request disclosed,
      lookupRequest a consent.sessionId = some request ∧
        disclosedSchemas a consent.selected = some disclosed ∧
        consent.requestCommitment = request.commitment ∧
        (∀ credentialId ∈ consent.selected, (lookupCredential a credentialId).isSome) ∧
        (∀ held ∈ disclosed, held ∈ request.requested) ∧
        (∀ want ∈ request.requested, want ∈ disclosed) ∧
        post.consumedNonces = a.consumedNonces ++ [request.nonce] := by
  unfold approvePresentation at accepted
  split at accepted
  case h_1 => exact absurd accepted (by simp)
  case h_2 request found =>
    split at accepted
    case isTrue => exact absurd accepted (by simp)
    case isFalse guard =>
      simp only [not_or, ne_eq, Classical.not_not] at guard
      split at accepted
      case h_1 => exact absurd accepted (by simp)
      case h_2 disclosed resolved =>
        split at accepted
        case isTrue cover =>
          refine ⟨request, disclosed, found, resolved, guard.2.2.1, ?_, cover.1, cover.2, ?_⟩
          · exact (disclosedSchemasAreHeld a consent.selected disclosed resolved).1
          · rw [← Option.some.inj accepted]
        case isFalse => exact absurd accepted (by simp)

/-! ## Rejection is a no-op -/

/-- Theorem 5: every rejected operation leaves the adapter state byte-identical. -/
theorem rejectedTransitionsPreserveState (a : Adapter) (s : Step) (rejected : step a s = none) :
    applyStep a s = a := by
  simp [applyStep, rejected]

/-- The registered credential table, session table, issuance table, presentation table, and consumed
nonce log are all unchanged by a rejected step. -/
theorem rejectedTransitionsPreserveEveryTable (a : Adapter) (s : Step) (rejected : step a s = none) :
    (applyStep a s).sessions = a.sessions ∧
      (applyStep a s).credentials = a.credentials ∧
      (applyStep a s).issuance = a.issuance ∧
      (applyStep a s).presentations = a.presentations ∧
      (applyStep a s).consumedNonces = a.consumedNonces := by
  rw [rejectedTransitionsPreserveState a s rejected]
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

end ActiveChain.OpenWalletConsent
