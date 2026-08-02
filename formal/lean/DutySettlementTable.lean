import ActiveChain.DutySettlement

open ActiveChain.DutySettlement

def render (name result : String) (state : State) (settlement : Option Settlement) : String :=
  let reward := (settlement.map Settlement.reward).getD 0
  let bondReturn := (settlement.map Settlement.bondReturn).getD 0
  let slash := (settlement.map Settlement.slashAmount).getD 0
  s!"{name},{result},{state.length},{settledCount state},{reward},{bondReturn},{slash}"

def dutyA : Assignment :=
  { id := 1, verifier := 2, bondAmount := 100, reward := 7, deadline := 10, settled := false }

def dutyB : Assignment :=
  { id := 2, verifier := 3, bondAmount := 200, reward := 9, deadline := 20, settled := false }

def dutyC : Assignment :=
  { id := 3, verifier := 4, bondAmount := 50, reward := 5, deadline := 5, settled := false }

def main : IO Unit := do
  let genesis : State := []
  IO.println (render "genesis" "accept" genesis none)
  let registered := (register genesis dutyA).get!
  IO.println (render "register" "accept" registered none)
  let duplicate := register registered dutyA
  IO.println
    (render "register_replay" (if duplicate.isSome then "accept" else "reject") registered none)
  let registered := (register registered dutyB).get!
  IO.println (render "register_second" "accept" registered none)
  let registered := (register registered dutyC).get!
  IO.println (render "register_third" "accept" registered none)

  let receiptA : Receipt := { assignment := 1, evidence := 9, height := 5 }
  let (settled, settlementA) := (settle registered receiptA 2 none).get!
  IO.println (render "settle" "accept" settled (some settlementA))

  let replay := settle settled receiptA 2 none
  IO.println
    (render "settle_replay" (if replay.isSome then "accept" else "reject")
      (applySettle settled receiptA 2 none) none)

  let receiptB : Receipt := { assignment := 2, evidence := 9, height := 12 }
  let faultB : Fault := { assignment := 2, slashAmount := 30 }
  let (slashed, settlementB) := (settle settled receiptB 3 (some faultB)).get!
  IO.println (render "settle_slashed" "accept" slashed (some settlementB))

  let expiredReceipt : Receipt := { assignment := 3, evidence := 9, height := 6 }
  let expired := settle slashed expiredReceipt 4 none
  IO.println
    (render "settle_expired" (if expired.isSome then "accept" else "reject")
      (applySettle slashed expiredReceipt 4 none) none)

  let receiptC : Receipt := { assignment := 3, evidence := 9, height := 4 }
  let wrongVerifier := settle slashed receiptC 99 none
  IO.println
    (render "settle_wrong_verifier" (if wrongVerifier.isSome then "accept" else "reject")
      (applySettle slashed receiptC 99 none) none)

  let emptyReceipt : Receipt := { assignment := 3, evidence := 0, height := 4 }
  let emptyEvidence := settle slashed emptyReceipt 4 none
  IO.println
    (render "settle_empty_evidence" (if emptyEvidence.isSome then "accept" else "reject")
      (applySettle slashed emptyReceipt 4 none) none)

  let excessFault : Fault := { assignment := 3, slashAmount := 60 }
  let excessSlash := settle slashed receiptC 4 (some excessFault)
  IO.println
    (render "settle_excess_slash" (if excessSlash.isSome then "accept" else "reject")
      (applySettle slashed receiptC 4 (some excessFault)) none)
