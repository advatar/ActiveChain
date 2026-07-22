import ActiveChain.EpochUpgrade

open ActiveChain.EpochUpgrade

def validatorAuthorization
    (finalized authorized activation fromEpoch toEpoch previousRoot nextRoot : Nat) :
    ValidatorSetAuthorization :=
  { finalized := finalized == 1
    authorizedAtHeight := authorized
    activationHeight := activation
    fromEpoch
    toEpoch
    previousRoot
    nextRoot }

def protocolAuthorization
    (finalized authorized activation previousRevision nextRevision : Nat) :
    ProtocolUpgradeAuthorization :=
  { finalized := finalized == 1
    authorizedAtHeight := authorized
    activationHeight := activation
    previousRevision
    nextRevision }

def render (name : String) (result : Option ChainState) : String :=
  match result with
  | none => s!"{name},reject,-,-,-"
  | some state =>
      s!"{name},accept,{state.epoch},{state.revision},{state.retiredValidatorSetRoots.length}"

def base : ChainState :=
  { height := 1
    epoch := 1
    validatorSetRoot := 1
    revision := 1
    retiredValidatorSetRoots := [] }

def unchangedValidator : ValidatorSetAuthorization :=
  validatorAuthorization 0 0 0 0 0 0 0

def unchangedProtocol : ProtocolUpgradeAuthorization :=
  protocolAuthorization 0 0 0 0 0

def cases : List (String × Option ChainState) :=
  [ ("validator_set", advance base
      { height := 2, epoch := 2, validatorSetRoot := 2, revision := 1 }
      { validatorSet := validatorAuthorization 1 1 2 1 2 1 2
        protocolUpgrade := unchangedProtocol })
  , ("protocol", advance base
      { height := 2, epoch := 1, validatorSetRoot := 1, revision := 2 }
      { validatorSet := unchangedValidator
        protocolUpgrade := protocolAuthorization 1 1 2 1 2 })
  , ("combined", advance base
      { height := 2, epoch := 2, validatorSetRoot := 2, revision := 2 }
      { validatorSet := validatorAuthorization 1 1 2 1 2 1 2
        protocolUpgrade := protocolAuthorization 1 1 2 1 2 })
  , ("wrong_height", advance base
      { height := 2, epoch := 2, validatorSetRoot := 2, revision := 1 }
      { validatorSet := validatorAuthorization 1 1 3 1 2 1 2
        protocolUpgrade := unchangedProtocol })
  , ("stale_context", advance base
      { height := 2, epoch := 2, validatorSetRoot := 2, revision := 1 }
      { validatorSet := validatorAuthorization 1 1 2 1 2 9 2
        protocolUpgrade := unchangedProtocol })
  , ("revision_downgrade", advance { base with revision := 2 }
      { height := 2, epoch := 1, validatorSetRoot := 1, revision := 1 }
      { validatorSet := unchangedValidator
        protocolUpgrade := protocolAuthorization 1 1 2 2 1 })
  , ("retired_root", advance
      { height := 2, epoch := 2, validatorSetRoot := 2, revision := 1,
        retiredValidatorSetRoots := [1] }
      { height := 3, epoch := 3, validatorSetRoot := 1, revision := 1 }
      { validatorSet := validatorAuthorization 1 2 3 2 3 2 1
        protocolUpgrade := unchangedProtocol })
  , ("history_full", advance
      { height := 65, epoch := 65, validatorSetRoot := 100, revision := 1,
        retiredValidatorSetRoots := List.range maxRetiredValidatorSetRoots }
      { height := 66, epoch := 66, validatorSetRoot := 200, revision := 1 }
      { validatorSet := validatorAuthorization 1 65 66 65 66 100 200
        protocolUpgrade := unchangedProtocol })
  ]

def main : IO Unit := do
  for (name, result) in cases do
    IO.println (render name result)
