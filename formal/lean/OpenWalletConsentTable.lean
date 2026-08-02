import ActiveChain.OpenWalletConsent

open ActiveChain.OpenWalletConsent

/-- The observable projection compared byte-for-byte against the production adapter: the open
session count, the held credential count, the issuance table size split by session state, the
pending presentation count, and the consumed nonce count. -/
def render (name result : String) (a : Adapter) : String :=
  s!"{name},{result},{a.sessions.length},{a.credentials.length},{a.issuance.length},\
{stateCount a IssuanceState.offered},{stateCount a IssuanceState.authorized},\
{stateCount a IssuanceState.completed},{a.presentations.length},{a.consumedNonces.length}"

def verdict (outcome : Option Adapter) : String :=
  if outcome.isSome then "accept" else "reject"

def issuanceSession : Session := { id := 1, relyingParty := 2, expiresAt := 20 }

/-- An honest offer: it enters the adapter in the `offered` state. -/
def honestOffer : Offer :=
  { session := issuanceSession
    grantNonce := 12
    consentDigest := 13
    state := IssuanceState.offered }

/-- The #678 attack shape: a wire-decoded offer that declares itself already authorized. -/
def preAuthorizedOffer : Offer :=
  { session := { id := 30, relyingParty := 31, expiresAt := 20 }
    grantNonce := 32
    consentDigest := 33
    state := IssuanceState.authorized }

/-- A fresh offer that replays an already spent grant nonce. -/
def replayedNonceOffer : Offer :=
  { session := { id := 80, relyingParty := 81, expiresAt := 20 }
    grantNonce := 12
    consentDigest := 84
    state := IssuanceState.offered }

def issuedCredential : CredentialRef := { credentialId := 50, schemaId := 51, issuer := 52 }
def replayCredential : CredentialRef := { credentialId := 60, schemaId := 61, issuer := 62 }
def unrelatedCredential : CredentialRef := { credentialId := 70, schemaId := 71, issuer := 72 }

def presentationRequest : Request :=
  { session := { id := 40, relyingParty := 41, expiresAt := 20 }
    nonce := 45
    commitment := 900
    requested := [51] }

def consentFor (selected : List Nat) : Consent :=
  { sessionId := 40, requestCommitment := 900, selected, expiresAt := 15 }

def main : IO Unit := do
  let genesis := empty
  IO.println (render "genesis" "accept" genesis)

  let opened := (beginIssuance genesis honestOffer 1).get!
  IO.println (render "begin_issuance" "accept" opened)

  let forged := beginIssuance opened preAuthorizedOffer 1
  IO.println
    (render "begin_issuance_pre_authorized" (verdict forged)
      (applyStep opened (Step.beginIssuance preAuthorizedOffer 1)))

  let wrongConsent := authorizeIssuance opened 1 99 5
  IO.println
    (render "authorize_wrong_consent" (verdict wrongConsent)
      (applyStep opened (Step.authorizeIssuance 1 99 5)))

  let authorized := (authorizeIssuance opened 1 13 5).get!
  IO.println (render "authorize" "accept" authorized)

  let completed := (completeIssuance authorized 1 issuedCredential 12 5).get!
  IO.println (render "complete" "accept" completed)

  let replay := completeIssuance completed 1 replayCredential 12 5
  IO.println
    (render "complete_replay" (verdict replay)
      (applyStep completed (Step.completeIssuance 1 replayCredential 12 5)))

  let stocked := (registerCredential completed unrelatedCredential).get!
  IO.println (render "register_unrelated_credential" "accept" stocked)

  let pending := (beginPresentation stocked presentationRequest 6).get!
  IO.println (render "begin_presentation" "accept" pending)

  let unrelated := approvePresentation pending (consentFor [70]) 7
  IO.println
    (render "approve_unrelated_schema" (verdict unrelated)
      (applyStep pending (Step.approvePresentation (consentFor [70]) 7)))

  let over := approvePresentation pending (consentFor [50, 70]) 7
  IO.println
    (render "approve_over_disclosure" (verdict over)
      (applyStep pending (Step.approvePresentation (consentFor [50, 70]) 7)))

  let approved := (approvePresentation pending (consentFor [50]) 7).get!
  IO.println (render "approve_exact" "accept" approved)

  let approvalReplay := approvePresentation approved (consentFor [50]) 7
  IO.println
    (render "approve_replay" (verdict approvalReplay)
      (applyStep approved (Step.approvePresentation (consentFor [50]) 7)))

  let nonceReplay := beginIssuance approved replayedNonceOffer 7
  IO.println
    (render "begin_issuance_replayed_nonce" (verdict nonceReplay)
      (applyStep approved (Step.beginIssuance replayedNonceOffer 7)))
