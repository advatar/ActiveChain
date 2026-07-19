import ActiveChain.Nonce

open ActiveChain.Nonce

def renderResult : AdvanceResult → String
  | .accepted nextSequence => s!"Accepted({nextSequence})"
  | .replay => "Replay"
  | .sequenceGap => "SequenceGap"
  | .sequenceExhausted => "SequenceExhausted"

def main : IO Unit := do
  for (expected, supplied, result) in nonceTable do
    IO.println s!"{expected},{supplied},{renderResult result}"
