/-!
# ActiveChain canonical envelope and verifier-boundary model

This dependency-free model fixes the fail-closed obligations of the canonical
codec, verifier API, verifier C ABI, and wallet session C ABI:

* an accepted envelope has the expected type and schema version;
* its length prefix is complete, bounded, and minimal;
* its body has exactly the declared length and no trailing bytes;
* commitment acceptance binds the selected domain and canonical body to the
  expected digest under the supplied hash function; and
* the C ABI rejects forbidden null-pointer/length combinations before calling
  the safe verifier, while the wallet session gate requires both fixed-size
  pointers and an unexpired session.

The parser observations below abstract Rust's byte-level big-endian and ULEB128
implementation.  SHAKE256 collision resistance and foreign-memory readability
are refinement assumptions, not Lean axioms.
-/

namespace ActiveChain.Envelope

abbrev Byte := Fin 256
abbrev Digest := Nat

def maxEnvelopeLength : Nat := 256 * 1024
def maxU32 : Nat := 4294967295

/-- Unique ULEB128 width for every protocol `u32` length. -/
def canonicalLengthWidth (value : Nat) : Nat :=
  if value < 2^7 then 1
  else if value < 2^14 then 2
  else if value < 2^21 then 3
  else if value < 2^28 then 4
  else 5

def MinimalLengthPrefix (value encodedWidth : Nat) : Prop :=
  value ≤ maxU32 ∧ encodedWidth = canonicalLengthWidth value

theorem minimalLengthWidthUnique
    (value firstWidth secondWidth : Nat)
    (first : MinimalLengthPrefix value firstWidth)
    (second : MinimalLengthPrefix value secondWidth) :
    firstWidth = secondWidth := by
  exact first.2.trans second.2.symm

theorem u32CanonicalWidthIsBounded
    (value : Nat) (fits : value ≤ maxU32) :
    1 ≤ canonicalLengthWidth value ∧ canonicalLengthWidth value ≤ 5 := by
  unfold canonicalLengthWidth
  split <;> split <;> split <;> split <;> omega

/-! ## Strict canonical-envelope inspection -/

/-- Observable results of parsing the untrusted envelope bytes.  This is the
refinement boundary for the Rust cursor and minimal ULEB128 decoder. -/
structure EnvelopeInput where
  encodedLength : Nat
  headerComplete : Bool
  typeTag : Nat
  schemaVersion : Nat
  lengthPrefixComplete : Bool
  lengthFitsU32 : Bool
  lengthMinimal : Bool
  declaredBodyLength : Nat
  body : List Byte
  trailingLength : Nat
  deriving BEq, DecidableEq, Repr

structure EnvelopeMetadata where
  typeTag : Nat
  schemaVersion : Nat
  bodyLength : Nat
  deriving BEq, DecidableEq, Repr

inductive VerifyError where
  | tooLarge
  | unexpectedEnd
  | typeMismatch
  | versionMismatch
  | nonMinimalLength
  | lengthOverflow
  | lengthLimitExceeded
  | bodyLengthMismatch
  | trailingData
  | commitmentMismatch
  | nullPointer
  deriving BEq, DecidableEq, Repr

/-- Stable numeric result classes exposed by `activechain-verifier-api` and
`activechain-verifier-ffi`.  Structural decoding failures intentionally share
code 2, matching the Rust adapter. -/
def VerifyError.code : VerifyError → Nat
  | .tooLarge => 1
  | .unexpectedEnd => 2
  | .typeMismatch => 3
  | .versionMismatch => 4
  | .nonMinimalLength => 2
  | .lengthOverflow => 2
  | .lengthLimitExceeded => 2
  | .bodyLengthMismatch => 2
  | .trailingData => 2
  | .commitmentMismatch => 5
  | .nullPointer => 6

def metadata (input : EnvelopeInput) : EnvelopeMetadata :=
  {
    typeTag := input.typeTag
    schemaVersion := input.schemaVersion
    bodyLength := input.body.length
  }

/-- Exact acceptance predicate for the verifier's structural envelope view. -/
def CanonicalFor
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput) : Prop :=
  input.encodedLength ≤ maxEnvelopeLength ∧
    input.headerComplete = true ∧
    input.typeTag = expectedType ∧
    input.schemaVersion = expectedVersion ∧
    input.lengthPrefixComplete = true ∧
    input.lengthFitsU32 = true ∧
    input.declaredBodyLength ≤ maxU32 ∧
    input.lengthMinimal = true ∧
    input.declaredBodyLength ≤ maximumBodyLength ∧
    input.body.length = input.declaredBodyLength ∧
    input.trailingLength = 0

instance canonicalForDecidable
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput) :
    Decidable (CanonicalFor expectedType expectedVersion maximumBodyLength input) := by
  unfold CanonicalFor
  infer_instance

/-- Structured failure classification in the same validation order as the Rust
boundary. -/
def classifyFailure
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput) : VerifyError :=
  if input.encodedLength > maxEnvelopeLength then
    .tooLarge
  else if input.headerComplete = false then
    .unexpectedEnd
  else if input.typeTag ≠ expectedType then
    .typeMismatch
  else if input.schemaVersion ≠ expectedVersion then
    .versionMismatch
  else if input.lengthPrefixComplete = false then
    .unexpectedEnd
  else if input.lengthFitsU32 = false ∨ input.declaredBodyLength > maxU32 then
    .lengthOverflow
  else if input.lengthMinimal = false then
    .nonMinimalLength
  else if input.declaredBodyLength > maximumBodyLength then
    .lengthLimitExceeded
  else if input.body.length ≠ input.declaredBodyLength then
    .bodyLengthMismatch
  else if input.trailingLength ≠ 0 then
    .trailingData
  else
    .bodyLengthMismatch

/-- Executable fail-closed inspection.  The specific body-schema decoder is a
subsequent refinement step. -/
def inspect
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput) : Except VerifyError EnvelopeMetadata :=
  if CanonicalFor expectedType expectedVersion maximumBodyLength input then
    .ok (metadata input)
  else
    .error (classifyFailure expectedType expectedVersion maximumBodyLength input)

theorem inspect_ok_iff
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput) :
    inspect expectedType expectedVersion maximumBodyLength input =
        .ok (metadata input) ↔
      CanonicalFor expectedType expectedVersion maximumBodyLength input := by
  simp [inspect]

theorem acceptedEnvelopeIsCanonical
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput) (result : EnvelopeMetadata)
    (accepted : inspect expectedType expectedVersion maximumBodyLength input = .ok result) :
    CanonicalFor expectedType expectedVersion maximumBodyLength input := by
  unfold inspect at accepted
  split at accepted
  · assumption
  · simp at accepted

theorem wrongTypeCannotBeAccepted
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput)
    (wrong : input.typeTag ≠ expectedType) :
    ∀ result,
      inspect expectedType expectedVersion maximumBodyLength input ≠ .ok result := by
  intro result accepted
  have canonical := acceptedEnvelopeIsCanonical
    expectedType expectedVersion maximumBodyLength input result accepted
  exact wrong canonical.2.2.1

theorem wrongVersionCannotBeAccepted
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput)
    (wrong : input.schemaVersion ≠ expectedVersion) :
    ∀ result,
      inspect expectedType expectedVersion maximumBodyLength input ≠ .ok result := by
  intro result accepted
  have canonical := acceptedEnvelopeIsCanonical
    expectedType expectedVersion maximumBodyLength input result accepted
  exact wrong canonical.2.2.2.1

theorem nonMinimalLengthCannotBeAccepted
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput)
    (nonMinimal : input.lengthMinimal = false) :
    ∀ result,
      inspect expectedType expectedVersion maximumBodyLength input ≠ .ok result := by
  intro result accepted
  have canonical := acceptedEnvelopeIsCanonical
    expectedType expectedVersion maximumBodyLength input result accepted
  exact Bool.noConfusion
    (nonMinimal.symm.trans canonical.2.2.2.2.2.2.2.1)

theorem wrongBodyLengthCannotBeAccepted
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput)
    (wrong : input.body.length ≠ input.declaredBodyLength) :
    ∀ result,
      inspect expectedType expectedVersion maximumBodyLength input ≠ .ok result := by
  intro result accepted
  have canonical := acceptedEnvelopeIsCanonical
    expectedType expectedVersion maximumBodyLength input result accepted
  exact wrong canonical.2.2.2.2.2.2.2.2.2.1

theorem trailingBytesCannotBeAccepted
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput)
    (trailing : input.trailingLength ≠ 0) :
    ∀ result,
      inspect expectedType expectedVersion maximumBodyLength input ≠ .ok result := by
  intro result accepted
  have canonical := acceptedEnvelopeIsCanonical
    expectedType expectedVersion maximumBodyLength input result accepted
  exact trailing canonical.2.2.2.2.2.2.2.2.2.2

theorem oversizedEnvelopeCannotBeAccepted
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput)
    (oversized : input.encodedLength > maxEnvelopeLength) :
    ∀ result,
      inspect expectedType expectedVersion maximumBodyLength input ≠ .ok result := by
  intro result accepted
  have canonical := acceptedEnvelopeIsCanonical
    expectedType expectedVersion maximumBodyLength input result accepted
  exact (Nat.not_lt_of_ge canonical.1) oversized

/-! ## Canonical-body commitment binding -/

def verifyCommitment
    (hash : List Byte → List Byte → Digest)
    (domain canonicalBody : List Byte) (expected : Digest) :
    Except VerifyError Unit :=
  if hash domain canonicalBody = expected then
    .ok ()
  else
    .error .commitmentMismatch

theorem verifyCommitment_ok_iff
    (hash : List Byte → List Byte → Digest)
    (domain canonicalBody : List Byte) (expected : Digest) :
    verifyCommitment hash domain canonicalBody expected = .ok () ↔
      hash domain canonicalBody = expected := by
  simp [verifyCommitment]

theorem acceptedCommitmentBindsDomainAndCanonicalBody
    (hash : List Byte → List Byte → Digest)
    (domain canonicalBody : List Byte) (expected : Digest)
    (accepted : verifyCommitment hash domain canonicalBody expected = .ok ()) :
    hash domain canonicalBody = expected := by
  exact (verifyCommitment_ok_iff hash domain canonicalBody expected).mp accepted

theorem observedCommitmentMismatchIsRejected
    (hash : List Byte → List Byte → Digest)
    (domain canonicalBody : List Byte) (expected : Digest)
    (mismatch : hash domain canonicalBody ≠ expected) :
    verifyCommitment hash domain canonicalBody expected =
      .error .commitmentMismatch := by
  simp [verifyCommitment, mismatch]

/-- End-to-end verifier abstraction: commitment verification receives only the
body selected by successful strict envelope inspection. -/
def inspectAndVerifyCommitment
    (hash : List Byte → List Byte → Digest)
    (domain : List Byte) (expectedDigest : Digest)
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput) : Except VerifyError EnvelopeMetadata :=
  match inspect expectedType expectedVersion maximumBodyLength input with
  | .error error => .error error
  | .ok result =>
      match verifyCommitment hash domain input.body expectedDigest with
      | .error error => .error error
      | .ok _ => .ok result

theorem acceptedEnvelopeCommitmentIsCanonicalAndBound
    (hash : List Byte → List Byte → Digest)
    (domain : List Byte) (expectedDigest : Digest)
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput) (result : EnvelopeMetadata)
    (accepted : inspectAndVerifyCommitment hash domain expectedDigest
      expectedType expectedVersion maximumBodyLength input = .ok result) :
    CanonicalFor expectedType expectedVersion maximumBodyLength input ∧
      hash domain input.body = expectedDigest := by
  cases inspection : inspect expectedType expectedVersion maximumBodyLength input with
  | error error => simp [inspectAndVerifyCommitment, inspection] at accepted
  | ok inspected =>
      cases commitment : verifyCommitment hash domain input.body expectedDigest with
      | error error =>
          simp [inspectAndVerifyCommitment, inspection, commitment] at accepted
      | ok value =>
          cases value
          have canonical := acceptedEnvelopeIsCanonical expectedType expectedVersion
            maximumBodyLength input inspected inspection
          have bound := (verifyCommitment_ok_iff hash domain input.body expectedDigest).mp
            (by simpa using commitment)
          exact ⟨canonical, bound⟩

/-! ## C ABI pointer/length gates -/

/-- Null is permitted only for a zero-length verifier input.  Readability of a
non-null foreign allocation remains a caller safety obligation. -/
def PointerLengthValid (pointerPresent : Bool) (length : Nat) : Prop :=
  pointerPresent = true ∨ length = 0

instance pointerLengthValidDecidable (pointerPresent : Bool) (length : Nat) :
    Decidable (PointerLengthValid pointerPresent length) := by
  unfold PointerLengthValid
  infer_instance

def resultCode {α : Type} : Except VerifyError α → Nat
  | .ok _ => 0
  | .error error => error.code

/-- Model of `activechain_inspect_envelope_code` before creation of the Rust
slice. -/
def ffiInspectCode
    (pointerPresent : Bool)
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput) : Nat :=
  if PointerLengthValid pointerPresent input.encodedLength then
    resultCode (inspect expectedType expectedVersion maximumBodyLength input)
  else
    VerifyError.nullPointer.code

theorem nullNonemptyVerifierInputMapsToCodeSix
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput) (nonempty : input.encodedLength ≠ 0) :
    ffiInspectCode false expectedType expectedVersion maximumBodyLength input = 6 := by
  simp [ffiInspectCode, PointerLengthValid, nonempty, VerifyError.code]

theorem validVerifierPointerDelegatesToSafeInspector
    (pointerPresent : Bool)
    (expectedType expectedVersion maximumBodyLength : Nat)
    (input : EnvelopeInput)
    (valid : PointerLengthValid pointerPresent input.encodedLength) :
    ffiInspectCode pointerPresent expectedType expectedVersion maximumBodyLength input =
      resultCode (inspect expectedType expectedVersion maximumBodyLength input) := by
  simp [ffiInspectCode, valid]

/-- Precondition of `activechain_verify_commitment_code`: variable buffers use
the null/zero rule and the fixed 48-byte digest pointer is always required. -/
def CommitmentAbiPrecondition
    (domainPointerPresent : Bool) (domainLength : Nat)
    (bodyPointerPresent : Bool) (bodyLength : Nat)
    (digestPointerPresent : Bool) : Prop :=
  PointerLengthValid domainPointerPresent domainLength ∧
    PointerLengthValid bodyPointerPresent bodyLength ∧
    digestPointerPresent = true

instance commitmentAbiPreconditionDecidable
    (domainPointerPresent : Bool) (domainLength : Nat)
    (bodyPointerPresent : Bool) (bodyLength : Nat)
    (digestPointerPresent : Bool) :
    Decidable (CommitmentAbiPrecondition domainPointerPresent domainLength
      bodyPointerPresent bodyLength digestPointerPresent) := by
  unfold CommitmentAbiPrecondition
  infer_instance

def ffiCommitmentCode
    (hash : List Byte → List Byte → Digest)
    (domain canonicalBody : List Byte) (expected : Digest)
    (domainPointerPresent bodyPointerPresent digestPointerPresent : Bool) : Nat :=
  if CommitmentAbiPrecondition domainPointerPresent domain.length
      bodyPointerPresent canonicalBody.length digestPointerPresent then
    resultCode (verifyCommitment hash domain canonicalBody expected)
  else
    VerifyError.nullPointer.code

theorem invalidCommitmentPointersMapToCodeSix
    (hash : List Byte → List Byte → Digest)
    (domain canonicalBody : List Byte) (expected : Digest)
    (domainPointerPresent bodyPointerPresent digestPointerPresent : Bool)
    (invalid : ¬ CommitmentAbiPrecondition domainPointerPresent domain.length
      bodyPointerPresent canonicalBody.length digestPointerPresent) :
    ffiCommitmentCode hash domain canonicalBody expected domainPointerPresent
      bodyPointerPresent digestPointerPresent = 6 := by
  simp [ffiCommitmentCode, invalid, VerifyError.code]

/-! ## Wallet session pointer/expiry gate -/

def WalletSessionPrecondition
    (sessionPointerPresent relyingPartyPointerPresent : Bool)
    (expiresAt height : Nat) : Prop :=
  sessionPointerPresent = true ∧
    relyingPartyPointerPresent = true ∧
    height ≤ expiresAt

instance walletSessionPreconditionDecidable
    (sessionPointerPresent relyingPartyPointerPresent : Bool)
    (expiresAt height : Nat) :
    Decidable (WalletSessionPrecondition sessionPointerPresent
      relyingPartyPointerPresent expiresAt height) := by
  unfold WalletSessionPrecondition
  infer_instance

def walletSessionValid
    (sessionPointerPresent relyingPartyPointerPresent : Bool)
    (expiresAt height : Nat) : Nat :=
  if WalletSessionPrecondition sessionPointerPresent relyingPartyPointerPresent
      expiresAt height then 1 else 0

theorem acceptedWalletSessionHasPointersAndIsUnexpired
    (sessionPointerPresent relyingPartyPointerPresent : Bool)
    (expiresAt height : Nat)
    (accepted : walletSessionValid sessionPointerPresent relyingPartyPointerPresent
      expiresAt height = 1) :
    WalletSessionPrecondition sessionPointerPresent relyingPartyPointerPresent
      expiresAt height := by
  unfold walletSessionValid at accepted
  split at accepted
  · assumption
  · simp at accepted

theorem expiredWalletSessionIsRejected
    (sessionPointerPresent relyingPartyPointerPresent : Bool)
    (expiresAt height : Nat) (expired : expiresAt < height) :
    walletSessionValid sessionPointerPresent relyingPartyPointerPresent
      expiresAt height = 0 := by
  simp [walletSessionValid, WalletSessionPrecondition]
  omega

end ActiveChain.Envelope
