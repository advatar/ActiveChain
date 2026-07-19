import ActiveChain.Object

open ActiveChain.ObjectModel

def renderBool : Bool → String
  | false => "false"
  | true => "true"

def renderResult : TransferResult → String
  | .success nextVersion => s!"Success({nextVersion})"
  | .authorizationDenied => "AuthorizationDenied"
  | .staleVersion => "StaleObjectVersion"
  | .versionExhausted => "VersionExhausted"

def main : IO Unit := do
  for (version, expectedVersion, authorized, result) in versionTable do
    IO.println s!"{version},{expectedVersion},{renderBool authorized},{renderResult result}"
