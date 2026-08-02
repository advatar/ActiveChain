import ActiveChain.DidLifecycle

open ActiveChain.DidLifecycle

def render (name result : String) (state : State) : String :=
  let sequence := ((lookup state 1).map Record.sequence).getD 0
  s!"{name},{result},{registeredCount state},{activeCount state},{sequence}"

def doc (principal control recovery : Nat) : Document :=
  { principal := principal
    methods := [{ id := control, purpose := .control }, { id := recovery, purpose := .recovery }] }

def record (document : Document) (sequence : Nat) (active : Bool) : Record :=
  { principal := document.principal, document := document, sequence := sequence, active := active }

def op (kind : Kind) (principal : Nat) (previous : Option Commitment) (next : Record) : Operation :=
  { kind := kind, principal := principal, previousCommitment := previous, next := next }

def step (state : State) (name : String) (operation : Operation) (authorizer : Nat) : IO State := do
  let result := if (apply state operation authorizer).isSome then "accept" else "reject"
  let next := applyStep state operation authorizer
  IO.println (render name result next)
  return next

def main : IO Unit := do
  let genesisDocument := doc 1 10 11
  let rotatedDocument := doc 1 13 14
  let recoveredDocument := doc 1 16 17
  let secondDocument := doc 2 20 21

  let first := record genesisDocument 1 true
  let rotated := record rotatedDocument 2 true
  let recovered := record recoveredDocument 3 true
  let deactivated := record recoveredDocument 4 false
  let posthumous := record recoveredDocument 5 true
  let second := record secondDocument 1 true

  let state : State := []
  IO.println (render "genesis" "accept" state)

  let state ← step state "create" (op .create 1 none first) 0
  let state ← step state "create_replay" (op .create 1 none first) 0
  let state ← step state "create_bad_sequence"
    (op .create 1 none (record genesisDocument 2 true)) 0
  let state ← step state "create_previous_commitment"
    (op .create 1 (some first.commitment) first) 0

  let state ← step state "update_recovery_authorizer"
    (op .update 1 (some first.commitment) rotated) 11
  let state ← step state "update_skips_sequence"
    (op .update 1 (some first.commitment) (record rotatedDocument 4 true)) 10
  let state ← step state "update" (op .update 1 (some first.commitment) rotated) 10
  let state ← step state "update_stale_commitment"
    (op .update 1 (some first.commitment) recovered) 13

  let state ← step state "recover_control_authorizer"
    (op .recover 1 (some rotated.commitment) recovered) 13
  let state ← step state "recover" (op .recover 1 (some rotated.commitment) recovered) 14

  let state ← step state "create_second_identity" (op .create 2 none second) 0

  let state ← step state "deactivate_recovery_authorizer"
    (op .deactivate 1 (some recovered.commitment) deactivated) 17
  let state ← step state "deactivate" (op .deactivate 1 (some recovered.commitment) deactivated) 16

  let state ← step state "update_after_deactivation"
    (op .update 1 (some deactivated.commitment) posthumous) 16
  let state ← step state "recover_after_deactivation"
    (op .recover 1 (some deactivated.commitment) posthumous) 17
  let _ ← step state "create_after_deactivation" (op .create 1 none first) 0
  pure ()
