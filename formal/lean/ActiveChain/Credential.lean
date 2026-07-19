/-!
# ActiveChain P-021 credential-status acceptance model

This executable model fixes the public development precedence for required,
future, stale, revoked, and suspended registry evidence independently of Rust.
-/

namespace ActiveChain.Credential

inductive CredentialStatus where
  | active
  | revoked
  | suspended
  deriving BEq, DecidableEq, Repr

inductive StatusResult where
  | accepted
  | statusRequired
  | registryFromFuture
  | registryStale
  | revoked
  | suspended
  deriving BEq, DecidableEq, Repr

def verifyStatus
    (declaresStatus requiresStatus : Bool)
    (presentationHeight effectiveHeight maximumAge : Nat)
    (status : CredentialStatus) : StatusResult :=
  if !declaresStatus then
    if requiresStatus then .statusRequired else .accepted
  else if effectiveHeight > presentationHeight then
    .registryFromFuture
  else if presentationHeight - effectiveHeight > maximumAge then
    .registryStale
  else
    match status with
    | .active => .accepted
    | .revoked => .revoked
    | .suspended => .suspended

@[simp] theorem missingRequiredStatusRejected
    (height effective maximumAge : Nat) (status : CredentialStatus) :
    verifyStatus false true height effective maximumAge status = .statusRequired := by
  simp [verifyStatus]

@[simp] theorem absentOptionalStatusAccepted
    (height effective maximumAge : Nat) (status : CredentialStatus) :
    verifyStatus false false height effective maximumAge status = .accepted := by
  simp [verifyStatus]

@[simp] theorem currentActiveRootAccepted
    (height maximumAge : Nat) (requiresStatus : Bool) :
    verifyStatus true requiresStatus height height maximumAge .active = .accepted := by
  simp [verifyStatus]

@[simp] theorem currentRevokedRootRejected
    (height maximumAge : Nat) (requiresStatus : Bool) :
    verifyStatus true requiresStatus height height maximumAge .revoked = .revoked := by
  simp [verifyStatus]

def credentialStatusCases : List (Bool × Bool × Nat × Nat × Nat × CredentialStatus) :=
  [
    (false, false, 50, 0, 5, .active),
    (false, true, 50, 0, 5, .active),
    (true, false, 50, 51, 5, .active),
    (true, false, 50, 44, 5, .active),
    (true, false, 50, 45, 5, .active),
    (true, true, 50, 45, 5, .revoked),
    (true, true, 50, 45, 5, .suspended)
  ]

def credentialStatusTable :
    List (Bool × Bool × Nat × Nat × Nat × CredentialStatus × StatusResult) :=
  credentialStatusCases.map fun (declares, requires, height, effective, maximumAge, status) =>
    (declares, requires, height, effective, maximumAge, status,
      verifyStatus declares requires height effective maximumAge status)

theorem credentialStatusTableHasSevenRows : credentialStatusTable.length = 7 := rfl

end ActiveChain.Credential
