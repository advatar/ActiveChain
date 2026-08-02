import ActiveChain.CashLifecycle

open ActiveChain.CashLifecycle

def render (name result : String) (state : State) : String :=
  s!"{name},{result},{state.supply},{state.shieldedPool},{state.redeemedRewards.length}"

def genesis : State :=
  { supply := 1000000, shieldedPool := 0, redeemedRewards := [], spentNullifiers := [] }

def main : IO Unit := do
  IO.println (render "genesis" "accept" genesis)
  let issued := (issue genesis 20).get!
  IO.println (render "issuance" "accept" issued)
  let rewarded := (redeemReward issued 90).get!
  IO.println (render "reward" "accept" rewarded)
  let rewardReplay := redeemReward rewarded 90
  IO.println (render "reward_replay" (if rewardReplay.isSome then "accept" else "reject") rewarded)
  let restarted := restart rewarded
  IO.println (render "restart" "accept" restarted)
  let shielded := (shield restarted 400).get!
  IO.println (render "shield" "accept" shielded)
  let unshielded := (unshield shielded 100 3 70).get!
  IO.println (render "unshield" "accept" unshielded)
  let unshieldReplay := unshield unshielded 100 3 70
  IO.println
    (render "unshield_replay" (if unshieldReplay.isSome then "accept" else "reject") unshielded)
