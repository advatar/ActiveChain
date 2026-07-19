import ActiveChain.ObjectVM

open ActiveChain.ObjectVM

def renderAction : Action → String
  | .copy => "Copy"
  | .move => "Move"
  | .consume => "Consume"

def renderKind : ValueKind → String
  | .u64 => "U64"
  | .bool => "Bool"
  | .digest => "Digest"
  | .object => "Object"
  | .capability => "Capability"

def renderVerdict : Verdict → String
  | .accept => "Accept"
  | .copyRequiresCopyable => "CopyRequiresCopyable"
  | .typeMismatch => "TypeMismatch"

def main : IO Unit := do
  for (action, kind, verdict, gasCost) in modelTable do
    IO.println s!"{renderAction action},{renderKind kind},{renderVerdict verdict},{gasCost}"
