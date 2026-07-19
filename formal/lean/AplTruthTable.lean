import ActiveChain.Apl

open ActiveChain.Apl

def renderBool : Bool → String
  | false => "false"
  | true => "true"

def renderDecision : Decision → String
  | .deny => "Deny"
  | .permit => "Permit"

def main : IO Unit := do
  for (hasPermit, hasForbid, decision) in truthTable do
    IO.println s!"{renderBool hasPermit},{renderBool hasForbid},{renderDecision decision}"
