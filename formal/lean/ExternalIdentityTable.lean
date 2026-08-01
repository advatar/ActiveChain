import ActiveChain.ExternalIdentity
open ActiveChain.ExternalIdentity

def bit (value : Bool) : String := if value then "1" else "0"
def row (value : String × Bool × Bool) : String :=
  value.1 ++ "\t" ++ bit value.2.1 ++ "\t" ++ bit value.2.2
def main : IO Unit :=
  IO.println <| String.intercalate "\n" ("case\tadmit\tauthorize" :: refinementTable.map row)
