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
def collectEffects : List RuleObservation → Bool × Bool
  | [] => (false, false)
  | rule :: rules => noteRule (collectEffects rules) rule

/-- P-023's complete default-deny, forbid-overrides decision table. -/
def combineEffects (hasPermit hasForbid : Bool) : Decision :=
  if hasPermit && !hasForbid then .permit else .deny

/-- Execute the effect layer over already-evaluated rule observations. -/
def evaluate (rules : List RuleObservation) : Decision :=
  let effects := collectEffects rules
  combineEffects effects.1 effects.2

/-- Logical, order-independent specification of whether a matching effect exists. -/
def hasMatchingEffect (effect : Effect) (rules : List RuleObservation) : Bool :=
  rules.any fun rule => rule.matched && (rule.effect == effect)

@[simp] theorem permitEqPermit : (Effect.permit == Effect.permit) = true := rfl
@[simp] theorem permitNeForbid : (Effect.permit == Effect.forbid) = false := rfl
@[simp] theorem forbidNePermit : (Effect.forbid == Effect.permit) = false := rfl
@[simp] theorem forbidEqForbid : (Effect.forbid == Effect.forbid) = true := rfl

theorem collectEffectsSpec (rules : List RuleObservation) :
    collectEffects rules =
      (hasMatchingEffect .permit rules, hasMatchingEffect .forbid rules) := by
  induction rules with
  | nil => rfl
  | cons rule rules ih =>
      cases rule with
      | mk effect matched =>
          cases effect <;> cases matched <;>
            simp [collectEffects, noteRule, hasMatchingEffect, ih]

@[simp] theorem defaultDeny : combineEffects false false = .deny := rfl

@[simp] theorem forbidPrecedence (hasPermit : Bool) :
    combineEffects hasPermit true = .deny := by
  cases hasPermit <;> rfl

theorem permitIff (hasPermit hasForbid : Bool) :
    combineEffects hasPermit hasForbid = .permit ↔
      hasPermit = true ∧ hasForbid = false := by
  cases hasPermit <;> cases hasForbid <;> decide

/-- A policy permits exactly when some permit matches and no forbid matches. -/
theorem evaluatePermitIff (rules : List RuleObservation) :
    evaluate rules = .permit ↔
      hasMatchingEffect .permit rules = true ∧
      hasMatchingEffect .forbid rules = false := by
  rw [evaluate, collectEffectsSpec]
  exact permitIff _ _

@[simp] theorem emptyPolicyDenies : evaluate [] = .deny := rfl

/-- Executable truth table consumed independently by the Rust exhaustive test. -/
def truthTable : List (Bool × Bool × Decision) :=
  [(false, false), (false, true), (true, false), (true, true)].map fun
    (hasPermit, hasForbid) =>
      (hasPermit, hasForbid, combineEffects hasPermit hasForbid)

theorem truthTableHasFourRows : truthTable.length = 4 := rfl

end ActiveChain.Apl
