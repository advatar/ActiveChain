import ActiveChain.ConsensusHistory

open ActiveChain.ConsensusHistory

def render (name : String) (result : Option RuntimeTraceState) : String :=
  match result with
  | none => s!"{name},reject,-,-,-"
  | some state =>
      s!"{name},accept,{state.finalizedHeight},{state.finalizedView},{state.activeEpoch}"

def initial : RuntimeTraceState :=
  { finalizedHeight := 0, finalizedView := 0, activeEpoch := 1 }

def skippedView : Option RuntimeTraceState :=
  finalizeRuntime initial 1 0 1

def restarted : Option RuntimeTraceState :=
  skippedView.map restartRuntime

def epochActivation : Option RuntimeTraceState := do
  let finalized ← finalizeRuntime initial 1 0 1
  activateRuntimeEpoch finalized 2

def postActivation : Option RuntimeTraceState := do
  let activated ← epochActivation
  finalizeRuntime activated 3 2 2

def cases : List (String × Option RuntimeTraceState) :=
  [ ("skipped_view", skippedView)
  , ("restart", restarted)
  , ("epoch_activation", epochActivation)
  , ("post_activation", postActivation)
  ]

def main : IO Unit := do
  for (name, result) in cases do
    IO.println (render name result)
