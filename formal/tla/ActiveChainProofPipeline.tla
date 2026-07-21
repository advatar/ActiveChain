----------------------- MODULE ActiveChainProofPipeline -----------------------
EXTENDS Integers, FiniteSets, TLC

(***************************************************************************
 * Bounded executable safety model for ActiveChain's proof-carrying block
 * pipeline.  The model explores two block heights, competing canonical order
 * batches, deterministic execution, a bounded proof-job queue, four prover
 * behaviours, retries, timeouts, proof replay, malformed proof delivery,
 * duplicate delivery, verification, finalization, and prover rewards.
 *
 * A proof is accepted only when both of these checks succeed:
 *
 *   1. the proof is cryptographically valid for its own public input; and
 *   2. that public input equals the target job's complete public input.
 *
 * The bound public input is the exact tuple
 *   <<height, pre-state, canonical order batch, post-state, block revision>>.
 * The post-state is recomputed by deterministic execution before a proof job
 * can enter the queue.  Finalization repeats the current-head checks so that
 * a proof accepted before a competing block finalized cannot later be replayed.
 *
 * This is a safety model.  Spec deliberately contains no fairness, delivery,
 * honest-prover availability, or synchrony assumption and therefore makes no
 * liveness claim.
 *)

Heights == 1..2
Revisions == 1..2

InitialState == "state-0"
StateAB == "state-ab"
StateBA == "state-ba"
StateABC == "state-ab-c"
StateBAC == "state-ba-c"
InvalidState == "invalid-state"

States == {InitialState, StateAB, StateBA, StateABC, StateBAC}

OrdersAB == "orders-a-b"
OrdersBA == "orders-b-a"
OrdersC == "orders-c"
OrderBatches == {OrdersAB, OrdersBA, OrdersC}

(***************************************************************************
 * Execute is a total, deterministic abstraction of canonical execution.  The
 * invalid result keeps malformed combinations executable without letting them
 * become proof jobs.
 *)

Execute(preState, orders, revision) ==
    CASE preState = InitialState /\ orders = OrdersAB /\ revision = 1 -> StateAB
      [] preState = InitialState /\ orders = OrdersBA /\ revision = 1 -> StateBA
      [] preState = StateAB /\ orders = OrdersC /\ revision = 2 -> StateABC
      [] preState = StateBA /\ orders = OrdersC /\ revision = 2 -> StateBAC
      [] OTHER -> InvalidState

JobAB == "job-height-1-ab"
JobBA == "job-height-1-ba"
JobABC == "job-height-2-ab-c"
JobBAC == "job-height-2-ba-c"
Jobs == {JobAB, JobBA, JobABC, JobBAC}

JobHeight == [j \in Jobs |->
    CASE j \in {JobAB, JobBA} -> 1
      [] j \in {JobABC, JobBAC} -> 2]

JobPreState == [j \in Jobs |->
    CASE j \in {JobAB, JobBA} -> InitialState
      [] j = JobABC -> StateAB
      [] j = JobBAC -> StateBA]

JobOrders == [j \in Jobs |->
    CASE j = JobAB -> OrdersAB
      [] j = JobBA -> OrdersBA
      [] j \in {JobABC, JobBAC} -> OrdersC]

JobRevision == [j \in Jobs |-> JobHeight[j]]

JobPostState == [j \in Jobs |->
    Execute(JobPreState[j], JobOrders[j], JobRevision[j])]

JobInput == [j \in Jobs |->
    [height |-> JobHeight[j],
     preState |-> JobPreState[j],
     orders |-> JobOrders[j],
     postState |-> JobPostState[j],
     blockRevision |-> JobRevision[j]]]

ExpectedRevision == [h \in Heights |-> h]

(***************************************************************************
 * Each job has one valid proof and one invalid proof that claims the same
 * public input.  A dishonest prover may submit any proof to any job, so TLC
 * explores valid proofs replayed across order batches, states, heights, and
 * revisions as well as invalid and malformed proof bytes.
 *)

ValidProofFor == [j \in Jobs |->
    CASE j = JobAB -> "proof-valid-ab"
      [] j = JobBA -> "proof-valid-ba"
      [] j = JobABC -> "proof-valid-ab-c"
      [] j = JobBAC -> "proof-valid-ba-c"]

InvalidProofFor == [j \in Jobs |->
    CASE j = JobAB -> "proof-invalid-ab"
      [] j = JobBA -> "proof-invalid-ba"
      [] j = JobABC -> "proof-invalid-ab-c"
      [] j = JobBAC -> "proof-invalid-ba-c"]

ValidProofs == {ValidProofFor[j] : j \in Jobs}
InvalidProofs == {InvalidProofFor[j] : j \in Jobs}
MalformedProof == "proof-malformed"
Proofs == ValidProofs \cup InvalidProofs \cup {MalformedProof}

NoJob == "no-job"
NoProof == "no-proof"
NoProver == "no-prover"

ProofSource(p) ==
    IF p = MalformedProof
    THEN NoJob
    ELSE CHOOSE j \in Jobs : p = ValidProofFor[j] \/ p = InvalidProofFor[j]

MalformedInput ==
    [height |-> 0,
     preState |-> InvalidState,
     orders |-> "malformed-orders",
     postState |-> InvalidState,
     blockRevision |-> 0]

ProofPublicInput(p) ==
    IF p = MalformedProof THEN MalformedInput ELSE JobInput[ProofSource(p)]

CryptographicallyValid(p) == p \in ValidProofs

ProofRelationHolds(p) ==
    /\ CryptographicallyValid(p)
    /\ LET input == ProofPublicInput(p) IN
       input.postState =
           Execute(input.preState, input.orders, input.blockRevision)

VerifierAccepts(j, p) ==
    /\ j \in Jobs
    /\ p \in Proofs
    /\ ProofRelationHolds(p)
    /\ ProofPublicInput(p) = JobInput[j]

HonestProver == "prover-honest"
DishonestProver == "prover-dishonest"
FailingProver == "prover-failing"
WithholdingProver == "prover-withholding"
Provers == {HonestProver, DishonestProver, FailingProver, WithholdingProver}

Absent == "absent"
Queued == "queued"
Assigned == "assigned"
Proved == "proved"
Failed == "failed"
Withheld == "withheld"
Accepted == "accepted"
Finalized == "finalized"
Discarded == "discarded"
Exhausted == "exhausted"

Statuses == {
    Absent, Queued, Assigned, Proved, Failed, Withheld, Accepted,
    Finalized, Discarded, Exhausted
}

LiveStatuses == {Queued, Assigned, Proved, Failed, Withheld, Accepted}
ActiveStatuses == {Assigned, Withheld}

MaxAttempts == 2
QueueCapacity == 2
ActiveCapacity == 1

VARIABLES
    status,
    attempts,
    assignedTo,
    submittedProof,
    acceptedProof,
    duplicateObserved,
    rewardCount,
    finalHeight,
    finalizedState,
    finalizedAt

vars == <<
    status,
    attempts,
    assignedTo,
    submittedProof,
    acceptedProof,
    duplicateObserved,
    rewardCount,
    finalHeight,
    finalizedState,
    finalizedAt
>>

EmptyJobTable(value) == [j \in Jobs |-> value]

Init ==
    /\ status = EmptyJobTable(Absent)
    /\ attempts = EmptyJobTable(0)
    /\ assignedTo = EmptyJobTable(NoProver)
    /\ submittedProof = EmptyJobTable(NoProof)
    /\ acceptedProof = EmptyJobTable(NoProof)
    /\ duplicateObserved = EmptyJobTable(FALSE)
    /\ rewardCount = [p \in Proofs |-> 0]
    /\ finalHeight = 0
    /\ finalizedState = InitialState
    /\ finalizedAt = [h \in Heights |-> NoJob]

QueueLoad == Cardinality({j \in Jobs : status[j] \in LiveStatuses})

ActiveLoad == Cardinality({j \in Jobs : status[j] \in ActiveStatuses})

WellFormedJob(j) ==
    /\ JobHeight[j] \in Heights
    /\ JobRevision[j] = ExpectedRevision[JobHeight[j]]
    /\ JobPostState[j] =
        Execute(JobPreState[j], JobOrders[j], JobRevision[j])
    /\ JobPostState[j] # InvalidState

CompatibleWithFinalizedHead(j) ==
    /\ WellFormedJob(j)
    /\ JobHeight[j] = finalHeight + 1
    /\ JobPreState[j] = finalizedState

Enqueue(j) ==
    /\ j \in Jobs
    /\ status[j] = Absent
    /\ CompatibleWithFinalizedHead(j)
    /\ QueueLoad < QueueCapacity
    /\ status' = [status EXCEPT ![j] = Queued]
    /\ UNCHANGED <<
        attempts, assignedTo, submittedProof, acceptedProof,
        duplicateObserved, rewardCount, finalHeight, finalizedState, finalizedAt
       >>

Assign(j, prover) ==
    /\ j \in Jobs
    /\ prover \in Provers
    /\ status[j] = Queued
    /\ attempts[j] < MaxAttempts
    /\ ActiveLoad < ActiveCapacity
    /\ status' = [status EXCEPT ![j] = Assigned]
    /\ attempts' = [attempts EXCEPT ![j] = @ + 1]
    /\ assignedTo' = [assignedTo EXCEPT ![j] = prover]
    /\ UNCHANGED <<
        submittedProof, acceptedProof, duplicateObserved, rewardCount,
        finalHeight, finalizedState, finalizedAt
       >>

ProduceHonestProof(j) ==
    /\ j \in Jobs
    /\ status[j] = Assigned
    /\ assignedTo[j] = HonestProver
    /\ status' = [status EXCEPT ![j] = Proved]
    /\ assignedTo' = [assignedTo EXCEPT ![j] = NoProver]
    /\ submittedProof' = [submittedProof EXCEPT ![j] = ValidProofFor[j]]
    /\ UNCHANGED <<
        attempts, acceptedProof, duplicateObserved, rewardCount,
        finalHeight, finalizedState, finalizedAt
       >>

ProduceDishonestProof(j, proof) ==
    /\ j \in Jobs
    /\ proof \in Proofs
    /\ status[j] = Assigned
    /\ assignedTo[j] = DishonestProver
    /\ status' = [status EXCEPT ![j] = Proved]
    /\ assignedTo' = [assignedTo EXCEPT ![j] = NoProver]
    /\ submittedProof' = [submittedProof EXCEPT ![j] = proof]
    /\ UNCHANGED <<
        attempts, acceptedProof, duplicateObserved, rewardCount,
        finalHeight, finalizedState, finalizedAt
       >>

FailProofAttempt(j) ==
    /\ j \in Jobs
    /\ status[j] = Assigned
    /\ assignedTo[j] = FailingProver
    /\ status' = [status EXCEPT ![j] = Failed]
    /\ assignedTo' = [assignedTo EXCEPT ![j] = NoProver]
    /\ submittedProof' = [submittedProof EXCEPT ![j] = NoProof]
    /\ UNCHANGED <<
        attempts, acceptedProof, duplicateObserved, rewardCount,
        finalHeight, finalizedState, finalizedAt
       >>

BeginWithholding(j) ==
    /\ j \in Jobs
    /\ status[j] = Assigned
    /\ assignedTo[j] = WithholdingProver
    /\ status' = [status EXCEPT ![j] = Withheld]
    /\ UNCHANGED <<
        attempts, assignedTo, submittedProof, acceptedProof,
        duplicateObserved, rewardCount, finalHeight, finalizedState, finalizedAt
       >>

TimeoutWithholder(j) ==
    /\ j \in Jobs
    /\ status[j] = Withheld
    /\ assignedTo[j] = WithholdingProver
    /\ status' = [status EXCEPT ![j] = Failed]
    /\ assignedTo' = [assignedTo EXCEPT ![j] = NoProver]
    /\ UNCHANGED <<
        attempts, submittedProof, acceptedProof, duplicateObserved, rewardCount,
        finalHeight, finalizedState, finalizedAt
       >>

AcceptProof(j) ==
    LET proof == submittedProof[j] IN
    /\ j \in Jobs
    /\ status[j] = Proved
    /\ VerifierAccepts(j, proof)
    /\ status' = [status EXCEPT ![j] = Accepted]
    /\ acceptedProof' = [acceptedProof EXCEPT ![j] = proof]
    /\ UNCHANGED <<
        attempts, assignedTo, submittedProof, duplicateObserved, rewardCount,
        finalHeight, finalizedState, finalizedAt
       >>

RejectProof(j) ==
    LET proof == submittedProof[j] IN
    /\ j \in Jobs
    /\ status[j] = Proved
    /\ ~VerifierAccepts(j, proof)
    /\ status' = [status EXCEPT ![j] = Failed]
    /\ submittedProof' = [submittedProof EXCEPT ![j] = NoProof]
    /\ UNCHANGED <<
        attempts, assignedTo, acceptedProof, duplicateObserved, rewardCount,
        finalHeight, finalizedState, finalizedAt
       >>

RetryFailedJob(j) ==
    /\ j \in Jobs
    /\ status[j] = Failed
    /\ attempts[j] < MaxAttempts
    /\ status' = [status EXCEPT ![j] = Queued]
    /\ UNCHANGED <<
        attempts, assignedTo, submittedProof, acceptedProof,
        duplicateObserved, rewardCount, finalHeight, finalizedState, finalizedAt
       >>

ExhaustFailedJob(j) ==
    /\ j \in Jobs
    /\ status[j] = Failed
    /\ attempts[j] = MaxAttempts
    /\ status' = [status EXCEPT ![j] = Exhausted]
    /\ UNCHANGED <<
        attempts, assignedTo, submittedProof, acceptedProof,
        duplicateObserved, rewardCount, finalHeight, finalizedState, finalizedAt
       >>

(***************************************************************************
 * Duplicate delivery is explicit.  It records one or more network replays as
 * an idempotent observation and cannot re-run verification, finalization, or
 * reward accounting.
 *)

ObserveDuplicateProof(j) ==
    /\ j \in Jobs
    /\ status[j] \in {Accepted, Finalized}
    /\ acceptedProof[j] \in Proofs
    /\ ~duplicateObserved[j]
    /\ duplicateObserved' = [duplicateObserved EXCEPT ![j] = TRUE]
    /\ UNCHANGED <<
        status, attempts, assignedTo, submittedProof, acceptedProof,
        rewardCount, finalHeight, finalizedState, finalizedAt
       >>

FinalizeProofCarryingBlock(j) ==
    LET proof == acceptedProof[j] IN
    /\ j \in Jobs
    /\ status[j] = Accepted
    /\ VerifierAccepts(j, proof)
    /\ CompatibleWithFinalizedHead(j)
    /\ finalizedAt[JobHeight[j]] = NoJob
    /\ rewardCount[proof] = 0
    /\ status' = [status EXCEPT ![j] = Finalized]
    /\ rewardCount' = [rewardCount EXCEPT ![proof] = @ + 1]
    /\ finalHeight' = JobHeight[j]
    /\ finalizedState' = JobPostState[j]
    /\ finalizedAt' = [finalizedAt EXCEPT ![JobHeight[j]] = j]
    /\ UNCHANGED <<
        attempts, assignedTo, submittedProof, acceptedProof, duplicateObserved
       >>

(***************************************************************************
 * Once a competing block advances the finalized head, any unfinished or
 * accepted job for the old head is stale.  Discarding it frees bounded queue
 * capacity but cannot change finalized state or pay a reward.
 *)

DiscardStaleJob(j) ==
    /\ j \in Jobs
    /\ status[j] \in LiveStatuses
    /\ ~CompatibleWithFinalizedHead(j)
    /\ status' = [status EXCEPT ![j] = Discarded]
    /\ assignedTo' = [assignedTo EXCEPT ![j] = NoProver]
    /\ submittedProof' = [submittedProof EXCEPT ![j] = NoProof]
    /\ UNCHANGED <<
        attempts, acceptedProof, duplicateObserved, rewardCount,
        finalHeight, finalizedState, finalizedAt
       >>

Next ==
    \/ \E j \in Jobs : Enqueue(j)
    \/ \E j \in Jobs, prover \in Provers : Assign(j, prover)
    \/ \E j \in Jobs : ProduceHonestProof(j)
    \/ \E j \in Jobs, proof \in Proofs : ProduceDishonestProof(j, proof)
    \/ \E j \in Jobs : FailProofAttempt(j)
    \/ \E j \in Jobs : BeginWithholding(j)
    \/ \E j \in Jobs : TimeoutWithholder(j)
    \/ \E j \in Jobs : AcceptProof(j)
    \/ \E j \in Jobs : RejectProof(j)
    \/ \E j \in Jobs : RetryFailedJob(j)
    \/ \E j \in Jobs : ExhaustFailedJob(j)
    \/ \E j \in Jobs : ObserveDuplicateProof(j)
    \/ \E j \in Jobs : FinalizeProofCarryingBlock(j)
    \/ \E j \in Jobs : DiscardStaleJob(j)

Spec == Init /\ [][Next]_vars

(***************************************************************************
 * State invariants checked exhaustively by TLC.
 *)

TypeOK ==
    /\ status \in [Jobs -> Statuses]
    /\ attempts \in [Jobs -> 0..MaxAttempts]
    /\ assignedTo \in [Jobs -> Provers \cup {NoProver}]
    /\ submittedProof \in [Jobs -> Proofs \cup {NoProof}]
    /\ acceptedProof \in [Jobs -> Proofs \cup {NoProof}]
    /\ duplicateObserved \in [Jobs -> BOOLEAN]
    /\ rewardCount \in [Proofs -> 0..2]
    /\ finalHeight \in 0..2
    /\ finalizedState \in States
    /\ finalizedAt \in [Heights -> Jobs \cup {NoJob}]

PipelineCapacityRespected ==
    /\ QueueLoad <= QueueCapacity
    /\ ActiveLoad <= ActiveCapacity

AssignmentAndProofCoherence ==
    /\ \A j \in Jobs :
        status[j] \in {Assigned, Withheld} <=> assignedTo[j] \in Provers
    /\ \A j \in Jobs :
        status[j] = Proved => submittedProof[j] \in Proofs
    /\ \A j \in Jobs :
        status[j] \in {Accepted, Finalized} => acceptedProof[j] \in Proofs
    /\ \A j \in Jobs :
        status[j] = Absent => attempts[j] = 0

NoInvalidOrMismatchedProofAccepted ==
    \A j \in Jobs :
        status[j] \in {Accepted, Finalized} =>
            VerifierAccepts(j, acceptedProof[j])

NoCrossJobProofReplayAccepted ==
    \A j \in Jobs :
        status[j] \in {Accepted, Finalized} =>
            ProofSource(acceptedProof[j]) = j

FinalizedProofsBindExactInputs ==
    \A h \in Heights :
        finalizedAt[h] # NoJob =>
            LET j == finalizedAt[h]
                proof == acceptedProof[j]
            IN
            /\ JobHeight[j] = h
            /\ status[j] = Finalized
            /\ VerifierAccepts(j, proof)
            /\ ProofPublicInput(proof) =
                [height |-> h,
                 preState |-> JobPreState[j],
                 orders |-> JobOrders[j],
                 postState |-> JobPostState[j],
                 blockRevision |-> ExpectedRevision[h]]
            /\ JobPostState[j] =
                Execute(JobPreState[j], JobOrders[j], JobRevision[j])

FinalizationIsSequentialAndDeterministic ==
    /\ (finalizedAt[2] # NoJob => finalizedAt[1] # NoJob)
    /\ \A h \in Heights :
        finalizedAt[h] # NoJob => JobHeight[finalizedAt[h]] = h
    /\ CASE finalHeight = 0 ->
            /\ finalizedState = InitialState
            /\ finalizedAt[1] = NoJob
            /\ finalizedAt[2] = NoJob
         [] finalHeight = 1 ->
            LET first == finalizedAt[1] IN
            /\ first # NoJob
            /\ finalizedAt[2] = NoJob
            /\ JobPreState[first] = InitialState
            /\ finalizedState = JobPostState[first]
         [] finalHeight = 2 ->
            LET first == finalizedAt[1]
                second == finalizedAt[2]
            IN
            /\ first # NoJob
            /\ second # NoJob
            /\ JobPreState[first] = InitialState
            /\ JobPreState[second] = JobPostState[first]
            /\ finalizedState = JobPostState[second]

NoProofRewardWithoutFinalization ==
    \A proof \in Proofs :
        rewardCount[proof] > 0 =>
            \E h \in Heights :
                LET j == finalizedAt[h] IN
                /\ j # NoJob
                /\ status[j] = Finalized
                /\ acceptedProof[j] = proof
                /\ VerifierAccepts(j, proof)

EveryFinalizedProofRewardedExactlyOnce ==
    \A h \in Heights :
        finalizedAt[h] # NoJob =>
            rewardCount[acceptedProof[finalizedAt[h]]] = 1

NoDuplicateProofRewards ==
    \A proof \in Proofs : rewardCount[proof] <= 1

(***************************************************************************
 * Action properties make the noninterference claim explicit: only the
 * finalization transition may mutate the finalized head/history or rewards.
 * Failure, withholding, timeout, retry, rejection, duplicate delivery, and
 * stale-job cleanup therefore cannot mutate committed state.
 *)

FinalizedStateChangesOnlyByFinalization ==
    [][(finalHeight' # finalHeight
         \/ finalizedState' # finalizedState
         \/ finalizedAt' # finalizedAt) =>
        \E j \in Jobs : FinalizeProofCarryingBlock(j)]_vars

RewardsChangeOnlyByFinalization ==
    [][rewardCount' # rewardCount =>
       \E j \in Jobs : FinalizeProofCarryingBlock(j)]_vars

=============================================================================
