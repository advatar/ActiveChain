------------------------- MODULE ActiveChainConsensus -------------------------
EXTENDS Integers, FiniteSets, TLC

(***************************************************************************
 * Bounded executable safety model for the ActiveChain consensus launch gate.
 *
 * The model is intentionally small enough for exhaustive TLC exploration:
 * four equal-weight validators, three honest validators, one Byzantine
 * validator, five globally ordered views, two validator-set roots, and one
 * authorized epoch transition.  A QC needs three votes.  The Byzantine
 * validator is conservatively counted as voting for every candidate, so every
 * modeled QC still requires two distinct honest validators.
 *
 * Honest votes are guarded by a HotStuff/Jolteon-style locked-QC rule:
 * vote for a proposal when it extends the durable lock, or when its parent QC
 * is strictly newer than the lock.  The proposal's parent is its justifying
 * QC.  A parent is committed by a consecutive two-QC chain.  This is a safety
 * model only; no fairness or liveness condition is part of Spec.
 *)

CONSTANTS V1, V2, V3, V4

Validators == {V1, V2, V3, V4}
Honest == {V1, V2, V3}
Byzantine == V4
Quorum == 3

Genesis == "genesis"
NoBlock == "no-block"
OldSet == "validator-set-0"
NewSet == "validator-set-1"

Rounds == 1..5
Epochs == {0, 1}

(***************************************************************************
 * Candidate graph.
 *
 * A1/B1 are conflicting first-view blocks.  A2/B2 are fresh first-height
 * proposals after a view change.  AC2/BC2 extend the first-view branches and
 * can commit A1/B1.  The round-three blocks exercise both continued branches
 * and new parents.  A1 is the sole modeled, already-authorized activation
 * checkpoint.  Epoch-one candidates must descend from A1.  Z4 is deliberately
 * rooted on the other branch and can never receive a conforming epoch-one
 * vote; it makes the activation-anchor check executable rather than vacuous.
 *)

EpochZeroBlocks == {
    "A1", "B1",
    "A2", "B2", "AC2", "BC2",
    "AD3", "BD3", "A2C3", "B2C3"
}

EpochOneBlocks == {"X4", "Y4", "Z4", "X5", "Y5"}

Blocks == EpochZeroBlocks \cup EpochOneBlocks
AllBlocks == Blocks \cup {Genesis}

Parent == [b \in Blocks |->
    CASE b \in {"A1", "B1", "A2", "B2"} -> Genesis
      [] b = "AC2" -> "A1"
      [] b = "BC2" -> "B1"
      [] b = "AD3" -> "AC2"
      [] b = "BD3" -> "BC2"
      [] b = "A2C3" -> "A2"
      [] b = "B2C3" -> "B2"
      [] b \in {"X4", "Y4"} -> "AC2"
      [] b = "Z4" -> "BC2"
      [] b = "X5" -> "X4"
      [] b = "Y5" -> "Y4"]

BlockRound == [b \in AllBlocks |->
    CASE b = Genesis -> 0
      [] b \in {"A1", "B1"} -> 1
      [] b \in {"A2", "B2", "AC2", "BC2"} -> 2
      [] b \in {"AD3", "BD3", "A2C3", "B2C3"} -> 3
      [] b \in {"X4", "Y4", "Z4"} -> 4
      [] b \in {"X5", "Y5"} -> 5]

BlockHeight == [b \in AllBlocks |->
    CASE b = Genesis -> 0
      [] b \in {"A1", "B1", "A2", "B2"} -> 1
      [] b \in {"AC2", "BC2", "A2C3", "B2C3"} -> 2
      [] b \in {"AD3", "BD3", "X4", "Y4", "Z4"} -> 3
      [] b \in {"X5", "Y5"} -> 4]

BlockEpoch == [b \in AllBlocks |->
    IF b \in EpochOneBlocks THEN 1 ELSE 0]

SetForEpoch == [e \in Epochs |-> IF e = 0 THEN OldSet ELSE NewSet]

TransitionBlock == "A1"

RECURSIVE Ancestors(_)
Ancestors(b) ==
    IF b = Genesis
    THEN {Genesis}
    ELSE {b} \cup Ancestors(Parent[b])

IsAncestorOrEqual(ancestor, descendant) == ancestor \in Ancestors(descendant)

VARIABLES
    voteAt,
    durableLock,
    durableView,
    online,
    crashLock,
    activeEpoch

vars == <<voteAt, durableLock, durableView, online, crashLock, activeEpoch>>

EmptyVoteTable == [r \in Rounds |-> NoBlock]

Init ==
    /\ voteAt = [v \in Honest |-> EmptyVoteTable]
    /\ durableLock = [v \in Honest |-> Genesis]
    /\ durableView = [v \in Honest |-> 1]
    /\ online = [v \in Honest |-> TRUE]
    /\ crashLock = [v \in Honest |-> NoBlock]
    /\ activeEpoch = 0

(***************************************************************************
 * The Byzantine validator may equivocate on every candidate.  Honest votes
 * are the durable table entries below.  Thus a three-of-four QC always needs
 * at least two honest votes even in the adversary's best case.
 *)

Voters(b) ==
    {Byzantine} \cup {v \in Honest : voteAt[v][BlockRound[b]] = b}

HasQC(b) == IF b = Genesis THEN TRUE ELSE Cardinality(Voters(b)) >= Quorum

Certified == {b \in Blocks : HasQC(b)}

CommitHeads == {
    p \in Blocks :
        HasQC(p)
        /\ \E child \in Blocks :
            /\ Parent[child] = p
            /\ HasQC(child)
            /\ BlockRound[child] = BlockRound[p] + 1
}

Committed == UNION {Ancestors(head) : head \in CommitHeads}

EpochOneAnchorOK(b) ==
    BlockEpoch[b] = 0 \/ IsAncestorOrEqual(TransitionBlock, b)

ProposalParentBound(b) ==
    /\ Parent[b] \in AllBlocks
    /\ HasQC(Parent[b])
    /\ BlockHeight[b] = BlockHeight[Parent[b]] + 1
    /\ BlockRound[b] > BlockRound[Parent[b]]
    /\ BlockEpoch[b] = activeEpoch
    /\ SetForEpoch[BlockEpoch[b]] = SetForEpoch[activeEpoch]
    /\ EpochOneAnchorOK(b)
    /\ (BlockEpoch[b] = 0 \/ TransitionBlock \in Committed)

SafeToVote(v, b) ==
    \/ IsAncestorOrEqual(durableLock[v], b)
    \/ BlockRound[Parent[b]] > BlockRound[durableLock[v]]

Vote(v, b) ==
    /\ v \in Honest
    /\ b \in Blocks
    /\ online[v]
    /\ durableView[v] = BlockRound[b]
    /\ voteAt[v][BlockRound[b]] = NoBlock
    /\ ProposalParentBound(b)
    /\ SafeToVote(v, b)
    /\ voteAt' = [voteAt EXCEPT ![v][BlockRound[b]] = b]
    /\ durableLock' =
        [durableLock EXCEPT
            ![v] = IF BlockRound[Parent[b]] > BlockRound[durableLock[v]]
                    THEN Parent[b]
                    ELSE durableLock[v]]
    /\ UNCHANGED <<durableView, online, crashLock, activeEpoch>>

AdvanceView(v) ==
    /\ v \in Honest
    /\ online[v]
    /\ durableView[v] < 5
    /\ durableView' = [durableView EXCEPT ![v] = @ + 1]
    /\ UNCHANGED <<voteAt, durableLock, online, crashLock, activeEpoch>>

(***************************************************************************
 * Crash and restart deliberately do not alter the vote table, view, or lock.
 * crashLock snapshots the lock and makes persistence an explicit invariant.
 *)

Crash(v) ==
    /\ v \in Honest
    /\ online[v]
    /\ online' = [online EXCEPT ![v] = FALSE]
    /\ crashLock' = [crashLock EXCEPT ![v] = durableLock[v]]
    /\ UNCHANGED <<voteAt, durableLock, durableView, activeEpoch>>

Restart(v) ==
    /\ v \in Honest
    /\ ~online[v]
    /\ crashLock[v] = durableLock[v]
    /\ online' = [online EXCEPT ![v] = TRUE]
    /\ crashLock' = [crashLock EXCEPT ![v] = NoBlock]
    /\ UNCHANGED <<voteAt, durableLock, durableView, activeEpoch>>

(***************************************************************************
 * The bounded reconfiguration is one-shot: the old set commits the
 * activation checkpoint, and the state moves from root 0 to root 1.  The
 * candidate graph preserves the same four identities to keep this first run
 * tractable; membership churn is a later refinement obligation.
 *)

ActivateNewValidatorSet ==
    /\ activeEpoch = 0
    /\ TransitionBlock \in Committed
    /\ activeEpoch' = 1
    /\ UNCHANGED <<voteAt, durableLock, durableView, online, crashLock>>

Next ==
    \/ \E v \in Honest, b \in Blocks : Vote(v, b)
    \/ \E v \in Honest : AdvanceView(v)
    \/ \E v \in Honest : Crash(v)
    \/ \E v \in Honest : Restart(v)
    \/ ActivateNewValidatorSet

Spec == Init /\ [][Next]_vars

(***************************************************************************
 * State and protocol invariants checked by TLC.
 *)

TypeOK ==
    /\ voteAt \in [Honest -> [Rounds -> Blocks \cup {NoBlock}]]
    /\ durableLock \in [Honest -> AllBlocks]
    /\ durableView \in [Honest -> Rounds]
    /\ online \in [Honest -> BOOLEAN]
    /\ crashLock \in [Honest -> AllBlocks \cup {NoBlock}]
    /\ activeEpoch \in Epochs

StaticFaultBound ==
    /\ Cardinality(Validators) = 4
    /\ Cardinality(Honest) = 3
    /\ Byzantine \in Validators
    /\ Byzantine \notin Honest

ASSUME ActiveSetHasOneByzantine == StaticFaultBound

Symmetry == Permutations(Honest)

DurableVoteDomain ==
    \A v \in Honest, r \in Rounds :
        voteAt[v][r] = NoBlock \/ BlockRound[voteAt[v][r]] = r

DurableLocksAreCertified ==
    \A v \in Honest : HasQC(durableLock[v])

OfflineLockMatchesCrashSnapshot ==
    \A v \in Honest : ~online[v] => crashLock[v] = durableLock[v]

QCParentAndViewBinding ==
    \A b \in Certified :
        /\ HasQC(Parent[b])
        /\ BlockHeight[b] = BlockHeight[Parent[b]] + 1
        /\ BlockRound[b] > BlockRound[Parent[b]]

NoConflictingQCsInOneView ==
    \A b1, b2 \in Certified :
        BlockRound[b1] = BlockRound[b2] => b1 = b2

NoConflictingCommitsAtOneHeight ==
    \A b1, b2 \in Committed :
        BlockHeight[b1] = BlockHeight[b2] => b1 = b2

PrefixComparableCommittedHistories ==
    \A b1, b2 \in Committed :
        IsAncestorOrEqual(b1, b2) \/ IsAncestorOrEqual(b2, b1)

EpochActivationRequiresOldSetCommit ==
    activeEpoch = 1 => TransitionBlock \in Committed

EpochOneCertificatesExtendActivationCheckpoint ==
    \A b \in Certified :
        BlockEpoch[b] = 1 => IsAncestorOrEqual(TransitionBlock, b)

=============================================================================
