/-!
# ActiveChain APL effect model

An executable, dependency-free reference for the consensus-critical effect
algebra in P-023. Wire decoding and predicate implementation remain Rust
refinement obligations; this model independently fixes default deny and forbid
precedence.
-/

namespace ActiveChain.Apl

inductive Effect where
  | permit
  | forbid
  deriving BEq, DecidableEq, Repr

inductive Decision where
  | deny
  | permit
  deriving BEq, DecidableEq, Repr

structure RuleObservation where
  effect : Effect
  matched : Bool
  deriving BEq, DecidableEq, Repr

/-- Record the existence of matching permit and forbid effects. -/
def noteRule (state : Bool × Bool) (rule : RuleObservation) : Bool × Bool :=
  if !rule.matched then
    state
  else
    match rule.effect with
    | .permit => (true, state.2)
    | .forbid => (state.1, true)

/-- Scan all rule results without order-sensitive effect combination. -/
def collectEffects (rules : List RuleObservation) : Bool × Bool :=
  rules.foldl noteRule (false, false)

/-- P-023's complete default-deny, forbid-overrides decision table. -/
def combineEffects (hasPermit hasForbid : Bool) : Decision :=
  if hasPermit && !hasForbid then .permit else .deny

/-- Execute the effect layer over already-evaluated rule observations. -/
def evaluate (rules : List RuleObservation) : Decision :=
  let effects := collectEffects rules
  combineEffects effects.1 effects.2

@[simp] theorem defaultDeny : combineEffects false false = .deny := rfl

@[simp] theorem forbidPrecedence (hasPermit : Bool) :
    combineEffects hasPermit true = .deny := by
  cases hasPermit <;> rfl

theorem permitIff (hasPermit hasForbid : Bool) :
    combineEffects hasPermit hasForbid = .permit ↔
      hasPermit = true ∧ hasForbid = false := by
  cases hasPermit <;> cases hasForbid <;> decide

@[simp] theorem emptyPolicyDenies : evaluate [] = .deny := rfl

/-- Executable truth table consumed independently by the Rust exhaustive test. -/
def truthTable : List (Bool × Bool × Decision) :=
  [(false, false), (false, true), (true, false), (true, true)].map fun
    (hasPermit, hasForbid) =>
      (hasPermit, hasForbid, combineEffects hasPermit hasForbid)

theorem truthTableHasFourRows : truthTable.length = 4 := rfl

end ActiveChain.Apl
