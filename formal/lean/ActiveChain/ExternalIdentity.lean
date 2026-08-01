/-! Bounded refinement model for P-096 through P-102 external identity admission. -/
namespace ActiveChain.ExternalIdentity

structure Inputs where
  issuerAuthentic : Bool
  schemaPinned : Bool
  holderBound : Bool
  statusFresh : Bool
  contextBound : Bool
  replayFresh : Bool
  assuranceAllowed : Bool
  minimized : Bool
  authenticatedActor : Bool
  capabilityValid : Bool
  approvalsValid : Bool
  aplPermit : Bool
  protocolForbid : Bool
  obligationsAtomic : Bool
  deriving BEq, Repr

def admit (i : Inputs) : Bool :=
  i.issuerAuthentic && i.schemaPinned && i.holderBound && i.statusFresh &&
  i.contextBound && i.replayFresh && i.assuranceAllowed && i.minimized

def authorize (i : Inputs) : Bool :=
  admit i && i.authenticatedActor && i.capabilityValid && i.approvalsValid &&
  i.aplPermit && !i.protocolForbid && i.obligationsAtomic

theorem issuer_authenticity (i : Inputs) : admit i = true → i.issuerAuthentic = true := by
  cases h : i.issuerAuthentic <;> simp_all [admit]
theorem schema_integrity (i : Inputs) : admit i = true → i.schemaPinned = true := by
  cases h : i.schemaPinned <;> simp_all [admit]
theorem holder_non_transferability (i : Inputs) : admit i = true → i.holderBound = true := by
  cases h : i.holderBound <;> simp_all [admit]
theorem status_freshness (i : Inputs) : admit i = true → i.statusFresh = true := by
  cases h : i.statusFresh <;> simp_all [admit]
theorem context_and_replay_safety (i : Inputs) :
    admit i = true → i.contextBound = true ∧ i.replayFresh = true := by
  intro admitted
  constructor
  · cases h : i.contextBound <;> simp_all [admit]
  · cases h : i.replayFresh <;> simp_all [admit]
theorem assurance_monotonicity (i : Inputs) : admit i = true → i.assuranceAllowed = true := by
  cases h : i.assuranceAllowed <;> simp_all [admit]
theorem disclosure_minimization (i : Inputs) : admit i = true → i.minimized = true := by
  cases h : i.minimized <;> simp_all [admit]
theorem no_authority_inflation (i : Inputs) :
    authorize i = true → i.capabilityValid = true ∧ i.approvalsValid = true := by
  intro authorized
  constructor
  · cases h : i.capabilityValid <;> simp_all [authorize, admit]
  · cases h : i.approvalsValid <;> simp_all [authorize, admit]
theorem forbid_dominates (i : Inputs) : i.protocolForbid = true → authorize i = false := by
  intro h
  simp [authorize, h]

structure PublicTrace where
  issuerCommitment : Nat
  schemaCommitment : Nat
  statusCommitment : Nat
  policyCommitment : Nat
  admitted : Bool
  deriving BEq, Repr

def project (issuer schema status policy : Nat) (i : Inputs) : PublicTrace :=
  ⟨issuer, schema, status, policy, admit i⟩

theorem declared_trace_only (issuer schema status policy : Nat) (i : Inputs) :
    (project issuer schema status policy i).admitted = admit i := rfl

def base : Inputs := ⟨true,true,true,true,true,true,true,true,true,true,true,true,false,true⟩
def cases : List (String × Inputs) := [
  ("valid", base),
  ("issuer", {base with issuerAuthentic := false}),
  ("schema", {base with schemaPinned := false}),
  ("holder", {base with holderBound := false}),
  ("status", {base with statusFresh := false}),
  ("context", {base with contextBound := false}),
  ("replay", {base with replayFresh := false}),
  ("assurance", {base with assuranceAllowed := false}),
  ("minimization", {base with minimized := false}),
  ("capability", {base with capabilityValid := false}),
  ("approval", {base with approvalsValid := false}),
  ("forbid", {base with protocolForbid := true})]

def refinementTable : List (String × Bool × Bool) :=
  cases.map fun (name, input) => (name, admit input, authorize input)
theorem refinement_table_has_twelve_rows : refinementTable.length = 12 := rfl

end ActiveChain.ExternalIdentity
