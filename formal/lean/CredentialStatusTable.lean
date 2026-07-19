import ActiveChain.Credential

open ActiveChain.Credential

def renderBool : Bool → String
  | true => "true"
  | false => "false"

def renderStatus : CredentialStatus → String
  | .active => "Active"
  | .revoked => "Revoked"
  | .suspended => "Suspended"

def renderResult : StatusResult → String
  | .accepted => "Accepted"
  | .statusRequired => "StatusRequired"
  | .registryFromFuture => "RegistryFromFuture"
  | .registryStale => "RegistryStale"
  | .revoked => "Revoked"
  | .suspended => "Suspended"

def main : IO Unit := do
  for (declares, requires, height, effective, maximumAge, status, result) in
      credentialStatusTable do
    IO.println s!"{renderBool declares},{renderBool requires},{height},{effective},{maximumAge},{renderStatus status},{renderResult result}"
