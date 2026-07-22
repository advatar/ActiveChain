import ActiveChain.Envelope

open ActiveChain.Envelope

def main : IO Unit := do
  for (value, width) in canonicalLengthWidthTable do
    IO.println s!"{value},{width}"
