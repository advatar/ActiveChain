/-!
# ActiveChain DID controller lifecycle refinement model

This executable model covers the `did:activechain` controller lifecycle shared by
`DidControllerOperationV1::new` and `DidControllerRecordV1::apply_document_operation` in
`crates/protocol-types/src/did.rs`: fresh-identity creation, strict sequence monotonicity,
previous-commitment binding, purpose-gated authorization, and terminal deactivation.

Commitment collision resistance, ML-DSA / SLH-DSA signature verification, canonical encoding,
authenticator validity windows, and key-agreement material are explicit production-boundary
assumptions. Identities, documents, and authenticator identifiers are modeled with `Nat`.
-/

namespace ActiveChain.DidLifecycle

/-- `AuthenticatorPurpose`, restricted to the two purposes a DID document may carry. -/
inductive Purpose where
  | control
  | recovery
  deriving BEq, DecidableEq, Inhabited, Repr

/-- `DidOperationKind`. -/
inductive Kind where
  | create
  | update
  | recover
  | deactivate
  deriving BEq, DecidableEq, Inhabited, Repr

/-- One authentication method of a DID document. Validity windows and key material are production
boundary concerns and are not modeled. -/
structure Method where
  id : Nat
  purpose : Purpose
  deriving BEq, DecidableEq, Inhabited, Repr

/-- `DidDocumentV1`, projected onto the identity and the authentication methods the lifecycle
rules actually read. -/
structure Document where
  principal : Nat
  methods : List Method
  deriving BEq, DecidableEq, Inhabited, Repr

/-- `DidControllerRecordV1`. The record commits to its document, so `matches_document` is document
equality here. -/
structure Record where
  principal : Nat
  document : Document
  sequence : Nat
  active : Bool
  deriving BEq, DecidableEq, Inhabited, Repr

/-- The production record commitment is SHAKE-256 over the canonical envelope. Collision resistance
is a production-boundary assumption, so a commitment is modeled by the record it commits to. -/
abbrev Commitment := Record

def Record.commitment (record : Record) : Commitment := record

/-- `DidControllerOperationV1`. The authorization commitment is a cryptographic binding and is left
to the production boundary. -/
structure Operation where
  kind : Kind
  principal : Nat
  previousCommitment : Option Commitment
  next : Record
  deriving BEq, DecidableEq, Inhabited, Repr

/-- The controller registry: one record per registered principal. -/
abbrev State := List Record

/-- Resolution finds the first registered record for a principal. -/
def lookup (state : State) (principal : Nat) : Option Record :=
  state.find? (fun record => record.principal == principal)

/-- Rewrites the registered record of one principal in place. -/
def replace (state : State) (principal : Nat) (next : Record) : State :=
  state.map (fun record => if record.principal = principal then next else record)

/-- `DidControllerOperationV1::new`: create carries no previous commitment, starts at sequence 1
and stays active; deactivate carries a previous commitment and clears active; update and recover
carry a previous commitment and stay active. -/
def Operation.wellFormed (op : Operation) : Bool :=
  op.principal != 0 && op.next.principal == op.principal &&
    match op.kind with
    | .create => op.previousCommitment.isNone && op.next.sequence == 1 && op.next.active
    | .deactivate => op.previousCommitment.isSome && !op.next.active
    | .update => op.previousCommitment.isSome && op.next.active
    | .recover => op.previousCommitment.isSome && op.next.active

/-- `current_document.method(authorizer)` followed by `method.purpose()`. -/
def authorizerPurpose (document : Document) (authorizer : Nat) : Option Purpose :=
  (document.methods.find? (fun method => method.id == authorizer)).map Method.purpose

/-- The `required` purpose of `apply_document_operation`. Create is rejected there outright, which
is modeled by `none`: creation is a registry admission, not a record transition. -/
def requiredPurpose : Kind → Option Purpose
  | .update => some .control
  | .deactivate => some .control
  | .recover => some .recovery
  | .create => none

/-- The record-transition guard of `apply_document_operation`: the record must still be active, the
operation must bind the exact current record commitment, it must advance the sequence by exactly
one, it must stay on the same principal, and the named authorizer must hold exactly the purpose the
operation kind requires. -/
def Accepts (current : Record) (op : Operation) (authorizer : Nat) : Prop :=
  current.active = true ∧
    op.previousCommitment = some current.commitment ∧
    op.next.sequence = current.sequence + 1 ∧
    op.next.principal = current.principal ∧
    authorizerPurpose current.document authorizer = requiredPurpose op.kind

instance (current : Record) (op : Operation) (authorizer : Nat) :
    Decidable (Accepts current op authorizer) := by
  unfold Accepts
  infer_instance

/-- The lifecycle transition. Create admits an unregistered principal; every other kind rewrites an
already registered record under the transition guard. A rejected operation yields `none`. -/
def apply (state : State) (op : Operation) (authorizer : Nat) : Option State :=
  if op.wellFormed = false then
    none
  else
    match op.kind with
    | .create =>
      match lookup state op.principal with
      | some _ => none
      | none => some (state ++ [op.next])
    | .update | .recover | .deactivate =>
      match lookup state op.principal with
      | none => none
      | some current =>
        if Accepts current op authorizer then
          some (replace state op.principal op.next)
        else
          none

/-- The state transition a node performs for one operation attempt: a rejected attempt is a no-op. -/
def applyStep (state : State) (op : Operation) (authorizer : Nat) : State :=
  (apply state op authorizer).getD state

/-- Sequential application of a lifecycle trace. -/
def run (state : State) (trace : List (Operation × Nat)) : State :=
  trace.foldl (fun current step => applyStep current step.1 step.2) state

def registeredCount (state : State) : Nat := state.length

def activeCount (state : State) : Nat := (state.filter (fun record => record.active)).length

/-! ## Registry lemmas -/

theorem lookupConsPos (head : Record) (tail : State) (principal : Nat)
    (hit : head.principal = principal) : lookup (head :: tail) principal = some head := by
  simp [lookup, hit]

theorem lookupConsNeg (head : Record) (tail : State) (principal : Nat)
    (miss : head.principal ≠ principal) :
    lookup (head :: tail) principal = lookup tail principal := by
  simp [lookup, miss]

theorem replaceCons (head : Record) (tail : State) (principal : Nat) (next : Record) :
    replace (head :: tail) principal next =
      (if head.principal = principal then next else head) :: replace tail principal next := rfl

/-- Every well-formed operation keeps its successor record on the operation's own principal. -/
theorem wellFormedBindsPrincipal (op : Operation) (formed : op.wellFormed = true) :
    op.next.principal = op.principal := by
  unfold Operation.wellFormed at formed
  simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq] at formed
  exact formed.1.2

/-- Rewriting the record of a principal leaves resolution of that principal pointing at the new
record, provided the new record keeps the principal. -/
theorem lookupReplaceSelf
    (state : State) (principal : Nat) (next current : Record)
    (bound : next.principal = principal)
    (found : lookup state principal = some current) :
    lookup (replace state principal next) principal = some next := by
  induction state with
  | nil => simp [lookup] at found
  | cons head tail ih =>
    rw [replaceCons]
    by_cases h : head.principal = principal
    · rw [if_pos h, lookupConsPos _ _ _ bound]
    · rw [if_neg h, lookupConsNeg _ _ _ h]
      exact ih (by rwa [lookupConsNeg _ _ _ h] at found)

/-- Rewriting the record of one principal never disturbs resolution of a different principal. -/
theorem lookupReplaceOther
    (state : State) (principal other : Nat) (next : Record)
    (bound : next.principal = principal)
    (distinct : other ≠ principal) :
    lookup (replace state principal next) other = lookup state other := by
  induction state with
  | nil => rfl
  | cons head tail ih =>
    rw [replaceCons]
    by_cases h : head.principal = principal
    · rw [if_pos h, lookupConsNeg _ _ _ (fun c => distinct (c.symm.trans bound)),
        lookupConsNeg _ _ _ (fun c => distinct (c.symm.trans h))]
      exact ih
    · rw [if_neg h]
      by_cases ho : head.principal = other
      · rw [lookupConsPos _ _ _ ho, lookupConsPos _ _ _ ho]
      · rw [lookupConsNeg _ _ _ ho, lookupConsNeg _ _ _ ho]
        exact ih

/-- Admitting a new principal never disturbs resolution of an already registered principal. -/
theorem lookupAppendResolved
    (state : State) (principal : Nat) (record next : Record)
    (found : lookup state principal = some record) :
    lookup (state ++ [next]) principal = some record := by
  unfold lookup at found ⊢
  rw [List.find?_append, found, Option.some_or]

/-- Resolution only ever returns a record that carries the resolved principal. -/
theorem lookupPrincipal
    (state : State) (principal : Nat) (record : Record)
    (found : lookup state principal = some record) : record.principal = principal := by
  unfold lookup at found
  simpa using List.find?_some found

/-! ## Theorems -/

/-- Theorem 1: creation requires a fresh identity. An accepted create carries no previous
commitment, starts the record at sequence 1, leaves the record active, and applies only to a
principal that is not already registered; the resulting registry is the old one extended by exactly
that record. -/
theorem createRequiresFreshIdentity
    (state post : State) (op : Operation) (authorizer : Nat)
    (isCreate : op.kind = .create)
    (accepted : apply state op authorizer = some post) :
    op.previousCommitment = none ∧
      op.next.sequence = 1 ∧
      op.next.active = true ∧
      op.next.principal = op.principal ∧
      lookup state op.principal = none ∧
      post = state ++ [op.next] := by
  unfold apply at accepted
  split at accepted
  case isTrue => exact absurd accepted (by simp)
  case isFalse formed =>
    have wf : op.wellFormed = true := by
      simpa using formed
    rw [Operation.wellFormed, isCreate] at wf
    simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq, Option.isNone_iff_eq_none] at wf
    obtain ⟨⟨_, bound⟩, ⟨⟨noPrevious, seqOne⟩, activeNext⟩⟩ := wf
    rw [isCreate] at accepted
    simp only at accepted
    split at accepted
    case h_1 => exact absurd accepted (by simp)
    case h_2 fresh =>
      exact ⟨noPrevious, seqOne, activeNext, bound, fresh, (Option.some.inj accepted).symm⟩

/-- The record-transition shape of every accepted non-create operation. -/
theorem transitionIsExact
    (state post : State) (op : Operation) (authorizer : Nat) (current : Record)
    (notCreate : op.kind ≠ .create)
    (found : lookup state op.principal = some current)
    (accepted : apply state op authorizer = some post) :
    current.active = true ∧
      op.previousCommitment = some current.commitment ∧
      op.next.sequence = current.sequence + 1 ∧
      op.next.principal = current.principal ∧
      authorizerPurpose current.document authorizer = requiredPurpose op.kind ∧
      post = replace state op.principal op.next := by
  unfold apply at accepted
  split at accepted
  case isTrue => exact absurd accepted (by simp)
  case isFalse =>
    have guard : Accepts current op authorizer ∧ post = replace state op.principal op.next := by
      cases hk : op.kind with
      | create => exact absurd hk notCreate
      | update =>
        rw [hk] at accepted
        simp only [found] at accepted
        split at accepted
        case isTrue g => exact ⟨g, (Option.some.inj accepted).symm⟩
        case isFalse => exact absurd accepted (by simp)
      | recover =>
        rw [hk] at accepted
        simp only [found] at accepted
        split at accepted
        case isTrue g => exact ⟨g, (Option.some.inj accepted).symm⟩
        case isFalse => exact absurd accepted (by simp)
      | deactivate =>
        rw [hk] at accepted
        simp only [found] at accepted
        split at accepted
        case isTrue g => exact ⟨g, (Option.some.inj accepted).symm⟩
        case isFalse => exact absurd accepted (by simp)
    obtain ⟨g, postEq⟩ := guard
    exact ⟨g.1, g.2.1, g.2.2.1, g.2.2.2.1, g.2.2.2.2, postEq⟩

/-- Theorem 2: the record sequence is strictly monotone. Every accepted update, recover, or
deactivate replaces the resolved record with one whose sequence is exactly one greater. -/
theorem sequenceIsStrictlyMonotone
    (state post : State) (op : Operation) (authorizer : Nat) (current : Record)
    (notCreate : op.kind ≠ .create)
    (found : lookup state op.principal = some current)
    (accepted : apply state op authorizer = some post) :
    lookup post op.principal = some op.next ∧ current.sequence < op.next.sequence := by
  obtain ⟨_, _, seq, bound, _, postEq⟩ :=
    transitionIsExact state post op authorizer current notCreate found accepted
  have principalEq : current.principal = op.principal := lookupPrincipal state op.principal current found
  subst postEq
  refine ⟨lookupReplaceSelf state op.principal op.next current (bound.trans principalEq) found, ?_⟩
  omega

/-- Theorem 3a: an accepted update, recover, or deactivate binds the exact current record
commitment. -/
theorem operationBindsPreviousCommitment
    (state post : State) (op : Operation) (authorizer : Nat) (current : Record)
    (notCreate : op.kind ≠ .create)
    (found : lookup state op.principal = some current)
    (accepted : apply state op authorizer = some post) :
    op.previousCommitment = some current.commitment :=
  (transitionIsExact state post op authorizer current notCreate found accepted).2.1

/-- Theorem 3b: a stale or foreign previous commitment is rejected. Any operation that does not
bind the exact current record commitment is refused, and applying it is a no-op. -/
theorem staleOrForeignCommitmentIsRejected
    (state : State) (op : Operation) (authorizer : Nat) (current : Record)
    (notCreate : op.kind ≠ .create)
    (found : lookup state op.principal = some current)
    (mismatch : op.previousCommitment ≠ some current.commitment) :
    apply state op authorizer = none ∧ applyStep state op authorizer = state := by
  have rejected : apply state op authorizer = none := by
    cases post : apply state op authorizer with
    | none => rfl
    | some value =>
      exact absurd
        (operationBindsPreviousCommitment state value op authorizer current notCreate found post)
        mismatch
  exact ⟨rejected, by simp [applyStep, rejected]⟩

/-- Theorem 4: deactivation is terminal. After an accepted deactivate, no operation on that
principal — of any kind, under any authorizer — is ever accepted again. -/
theorem deactivationIsTerminal
    (state post : State) (op : Operation) (authorizer : Nat) (current : Record)
    (isDeactivate : op.kind = .deactivate)
    (found : lookup state op.principal = some current)
    (accepted : apply state op authorizer = some post)
    (later : Operation) (laterAuthorizer : Nat)
    (samePrincipal : later.principal = op.principal) :
    apply post later laterAuthorizer = none := by
  have notCreate : op.kind ≠ .create := by simp [isDeactivate]
  have inactive : op.next.active = false := by
    unfold apply at accepted
    split at accepted
    case isTrue => exact absurd accepted (by simp)
    case isFalse formed =>
      have wf : op.wellFormed = true := by simpa using formed
      rw [Operation.wellFormed, isDeactivate] at wf
      simp only [Bool.and_eq_true, Bool.not_eq_true'] at wf
      exact wf.2.2
  obtain ⟨resolved, _⟩ :=
    sequenceIsStrictlyMonotone state post op authorizer current notCreate found accepted
  have resolvedLater : lookup post later.principal = some op.next := by
    rw [samePrincipal]; exact resolved
  unfold apply
  split
  case isTrue => rfl
  case isFalse =>
    cases hk : later.kind with
    | create => simp [resolvedLater]
    | update => simp [hk, resolvedLater, Accepts, inactive]
    | recover => simp [hk, resolvedLater, Accepts, inactive]
    | deactivate => simp [hk, resolvedLater, Accepts, inactive]

/-- Theorem 5: every rejected operation leaves the registry byte-identical. -/
theorem rejectedOperationsPreserveState
    (state : State) (op : Operation) (authorizer : Nat)
    (rejected : apply state op authorizer = none) :
    applyStep state op authorizer = state := by
  simp [applyStep, rejected]

/-- Theorem 6: a control authenticator can never authorize a recovery. The production
`required` purpose for `Recover` is `AuthenticatorPurpose::Recovery`, and the purpose match is
exact. -/
theorem controlCannotAuthorizeRecovery
    (state : State) (op : Operation) (authorizer : Nat) (current : Record)
    (isRecover : op.kind = .recover)
    (found : lookup state op.principal = some current)
    (control : authorizerPurpose current.document authorizer = some .control) :
    apply state op authorizer = none := by
  cases post : apply state op authorizer with
  | none => rfl
  | some value =>
    have notCreate : op.kind ≠ .create := by simp [isRecover]
    obtain ⟨_, _, _, _, purpose, _⟩ :=
      transitionIsExact state value op authorizer current notCreate found post
    rw [control, isRecover] at purpose
    exact absurd purpose (by simp [requiredPurpose])

/-- Symmetrically, a recovery authenticator can never authorize an update or a deactivation. -/
theorem recoveryCannotAuthorizeUpdateOrDeactivate
    (state : State) (op : Operation) (authorizer : Nat) (current : Record)
    (controlKind : op.kind = .update ∨ op.kind = .deactivate)
    (found : lookup state op.principal = some current)
    (recovery : authorizerPurpose current.document authorizer = some .recovery) :
    apply state op authorizer = none := by
  cases post : apply state op authorizer with
  | none => rfl
  | some value =>
    have notCreate : op.kind ≠ .create := by
      rcases controlKind with h | h <;> simp [h]
    obtain ⟨_, _, _, _, purpose, _⟩ :=
      transitionIsExact state value op authorizer current notCreate found post
    rw [recovery] at purpose
    rcases controlKind with h | h <;> rw [h] at purpose <;>
      exact absurd purpose (by simp [requiredPurpose])

/-- A record that is already registered can never be created again: a duplicate create is
rejected. -/
theorem createRejectsRegisteredIdentity
    (state : State) (op : Operation) (authorizer : Nat) (current : Record)
    (isCreate : op.kind = .create)
    (registered : lookup state op.principal = some current) :
    apply state op authorizer = none := by
  cases post : apply state op authorizer with
  | none => rfl
  | some value =>
    obtain ⟨_, _, _, _, fresh, _⟩ :=
      createRequiresFreshIdentity state value op authorizer isCreate post
    exact absurd registered (by simp [fresh])

/-! ## Trace-level terminality -/

/-- One step never disturbs an inactive record: create on that principal is a duplicate, every
other kind fails the active guard, and operations on other principals rewrite or extend elsewhere. -/
theorem inactiveRecordSurvivesOneStep
    (state : State) (principal : Nat) (record : Record) (op : Operation) (authorizer : Nat)
    (found : lookup state principal = some record)
    (inactive : record.active = false) :
    lookup (applyStep state op authorizer) principal = some record := by
  unfold applyStep apply
  split
  case isTrue => simpa using found
  case isFalse formed =>
    have bound : op.next.principal = op.principal :=
      wellFormedBindsPrincipal op (by simpa using formed)
    by_cases same : op.principal = principal
    · subst same
      cases hk : op.kind with
      | create => simp [found]
      | update => simp [hk, found, Accepts, inactive]
      | recover => simp [hk, found, Accepts, inactive]
      | deactivate => simp [hk, found, Accepts, inactive]
    · have distinct : principal ≠ op.principal := fun h => same h.symm
      cases hk : op.kind with
      | create =>
        cases other : lookup state op.principal with
        | none => simpa [hk, other] using lookupAppendResolved state principal record op.next found
        | some value => simpa [hk, other] using found
      | update =>
        cases other : lookup state op.principal with
        | none => simpa [hk, other] using found
        | some value =>
          by_cases g : Accepts value op authorizer
          · simpa [hk, other, g] using
              (lookupReplaceOther state op.principal principal op.next bound distinct).trans found
          · simpa [hk, other, g] using found
      | recover =>
        cases other : lookup state op.principal with
        | none => simpa [hk, other] using found
        | some value =>
          by_cases g : Accepts value op authorizer
          · simpa [hk, other, g] using
              (lookupReplaceOther state op.principal principal op.next bound distinct).trans found
          · simpa [hk, other, g] using found
      | deactivate =>
        cases other : lookup state op.principal with
        | none => simpa [hk, other] using found
        | some value =>
          by_cases g : Accepts value op authorizer
          · simpa [hk, other, g] using
              (lookupReplaceOther state op.principal principal op.next bound distinct).trans found
          · simpa [hk, other, g] using found

/-- Theorem 4, trace form: once a record is inactive, no lifecycle trace of any length, over any
principals and any authorizers, can ever change it. -/
theorem inactiveRecordSurvivesEveryTrace
    (state : State) (principal : Nat) (record : Record)
    (found : lookup state principal = some record)
    (inactive : record.active = false)
    (trace : List (Operation × Nat)) :
    lookup (run state trace) principal = some record := by
  induction trace generalizing state with
  | nil => simpa [run] using found
  | cons step rest ih =>
    have next := inactiveRecordSurvivesOneStep state principal record step.1 step.2 found inactive
    simpa [run, List.foldl_cons] using ih (applyStep state step.1 step.2) next

end ActiveChain.DidLifecycle
