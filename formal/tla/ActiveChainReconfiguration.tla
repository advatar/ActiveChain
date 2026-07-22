---------------------- MODULE ActiveChainReconfiguration ----------------------
EXTENDS Integers, FiniteSets, Sequences, TLC

(***************************************************************************
 * Bounded membership-churn and timed-liveness model.
 *
 * Three four-validator sets execute two authorized transitions. Each step
 * removes one validator and admits one validator. Certificates bind the
 * epoch and exact active set. Retired sets can present stale certificates,
 * but admission records their rejection rather than changing protocol state.
 * Locks, certificates, and commits survive crashes. The liveness
 * specification disables crashes and assumes weak fairness for the clock,
 * timeout, delivery, proposal, certificate, commit, authorization, and
 * activation actions.
 *************************************************************************)

CONSTANTS V1, V2, V3, V4, V5, V6, MaxView, Deadline, NetworkDelay,
          EnableCrashes

Validators == {V1, V2, V3, V4, V5, V6}
Epochs == 0..2
Values == {"left", "right"}
NoValue == "none"
Phases == {"idle", "proposed", "certified", "committed"}

Set0 == {V1, V2, V3, V4}
Set1 == {V1, V2, V3, V5}
Set2 == {V1, V2, V5, V6}
Membership == [e \in Epochs |-> CASE e = 0 -> Set0 [] e = 1 -> Set1 [] OTHER -> Set2]

VARIABLES epoch, activeSet, retiredSets, transitionCount, authorized,
          phase, proposal, certificateEpoch, certificateSet, durableLock,
          committed, online, crashSnapshot, view, clock, delivered,
          staleRejected

vars == <<epoch, activeSet, retiredSets, transitionCount, authorized,
          phase, proposal, certificateEpoch, certificateSet, durableLock,
          committed, online, crashSnapshot, view, clock, delivered,
          staleRejected>>

Init ==
    /\ epoch = 0
    /\ activeSet = Set0
    /\ retiredSets = {}
    /\ transitionCount = 0
    /\ authorized = FALSE
    /\ phase = "idle"
    /\ proposal = NoValue
    /\ certificateEpoch = -1
    /\ certificateSet = {}
    /\ durableLock = NoValue
    /\ committed = <<>>
    /\ online = TRUE
    /\ crashSnapshot = NoValue
    /\ view = 0
    /\ clock = 0
    /\ delivered = FALSE
    /\ staleRejected = 0

HonestLeader == view % 3 = 2

Tick ==
    /\ online
    /\ clock < Deadline
    /\ clock' = clock + 1
    /\ UNCHANGED <<epoch, activeSet, retiredSets, transitionCount, authorized,
                    phase, proposal, certificateEpoch, certificateSet,
                    durableLock, committed, online, crashSnapshot, view,
                    delivered, staleRejected>>

Deliver ==
    /\ online
    /\ ~delivered
    /\ clock >= NetworkDelay
    /\ delivered' = TRUE
    /\ UNCHANGED <<epoch, activeSet, retiredSets, transitionCount, authorized,
                    phase, proposal, certificateEpoch, certificateSet,
                    durableLock, committed, online, crashSnapshot, view, clock,
                    staleRejected>>

Timeout ==
    /\ online
    /\ clock = Deadline
    /\ view < MaxView
    /\ view' = view + 1
    /\ clock' = 0
    /\ delivered' = FALSE
    /\ phase' = IF phase = "proposed" THEN "idle" ELSE phase
    /\ proposal' = IF phase = "proposed" THEN NoValue ELSE proposal
    /\ UNCHANGED <<epoch, activeSet, retiredSets, transitionCount, authorized,
                    certificateEpoch, certificateSet, durableLock, committed,
                    online, crashSnapshot, staleRejected>>

Propose(value) ==
    /\ online
    /\ delivered
    /\ HonestLeader
    /\ phase = "idle"
    /\ value \in Values
    /\ (durableLock = NoValue \/ durableLock = value)
    /\ proposal' = value
    /\ phase' = "proposed"
    /\ UNCHANGED <<epoch, activeSet, retiredSets, transitionCount, authorized,
                    certificateEpoch, certificateSet, durableLock, committed,
                    online, crashSnapshot, view, clock, delivered,
                    staleRejected>>

Certify ==
    /\ online
    /\ delivered
    /\ phase = "proposed"
    /\ activeSet = Membership[epoch]
    /\ certificateEpoch' = epoch
    /\ certificateSet' = activeSet
    /\ durableLock' = proposal
    /\ phase' = "certified"
    /\ UNCHANGED <<epoch, activeSet, retiredSets, transitionCount, authorized,
                    proposal, committed, online, crashSnapshot, view, clock,
                    delivered, staleRejected>>

Commit ==
    /\ online
    /\ phase = "certified"
    /\ certificateEpoch = epoch
    /\ certificateSet = activeSet
    /\ committed' = Append(committed, [epoch |-> epoch, value |-> proposal,
                                        set |-> activeSet])
    /\ phase' = "committed"
    /\ UNCHANGED <<epoch, activeSet, retiredSets, transitionCount, authorized,
                    proposal, certificateEpoch, certificateSet, durableLock,
                    online, crashSnapshot, view, clock, delivered,
                    staleRejected>>

Authorize ==
    /\ epoch < 2
    /\ phase = "committed"
    /\ ~authorized
    /\ authorized' = TRUE
    /\ UNCHANGED <<epoch, activeSet, retiredSets, transitionCount, phase,
                    proposal, certificateEpoch, certificateSet, durableLock,
                    committed, online, crashSnapshot, view, clock, delivered,
                    staleRejected>>

Activate ==
    /\ epoch < 2
    /\ online
    /\ authorized
    /\ phase = "committed"
    /\ retiredSets' = retiredSets \cup {activeSet}
    /\ epoch' = epoch + 1
    /\ activeSet' = Membership[epoch + 1]
    /\ transitionCount' = transitionCount + 1
    /\ authorized' = FALSE
    /\ phase' = "idle"
    /\ proposal' = NoValue
    /\ certificateEpoch' = -1
    /\ certificateSet' = {}
    /\ view' = 0
    /\ clock' = 0
    /\ delivered' = FALSE
    /\ UNCHANGED <<durableLock, committed, online, crashSnapshot, staleRejected>>

RejectRetiredCertificate ==
    /\ retiredSets # {}
    /\ staleRejected < 2
    /\ staleRejected' = staleRejected + 1
    /\ UNCHANGED <<epoch, activeSet, retiredSets, transitionCount, authorized,
                    phase, proposal, certificateEpoch, certificateSet,
                    durableLock, committed, online, crashSnapshot, view, clock,
                    delivered>>

Crash ==
    /\ EnableCrashes
    /\ online
    /\ online' = FALSE
    /\ crashSnapshot' = durableLock
    /\ UNCHANGED <<epoch, activeSet, retiredSets, transitionCount, authorized,
                    phase, proposal, certificateEpoch, certificateSet,
                    durableLock, committed, view, clock, delivered,
                    staleRejected>>

Restart ==
    /\ EnableCrashes
    /\ ~online
    /\ crashSnapshot = durableLock
    /\ online' = TRUE
    /\ crashSnapshot' = NoValue
    /\ UNCHANGED <<epoch, activeSet, retiredSets, transitionCount, authorized,
                    phase, proposal, certificateEpoch, certificateSet,
                    durableLock, committed, view, clock, delivered,
                    staleRejected>>

Next ==
    Tick \/ Deliver \/ Timeout \/ (\E value \in Values : Propose(value)) \/
    Certify \/ Commit \/ Authorize \/ Activate \/ RejectRetiredCertificate \/
    Crash \/ Restart

SafetySpec == Init /\ [][Next]_vars

LivenessSpec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(Tick)
    /\ WF_vars(Deliver)
    /\ WF_vars(Timeout)
    /\ WF_vars(\E value \in Values : Propose(value))
    /\ WF_vars(Certify)
    /\ WF_vars(Commit)
    /\ WF_vars(Authorize)
    /\ WF_vars(Activate)

TypeOK ==
    /\ epoch \in Epochs
    /\ activeSet \subseteq Validators
    /\ retiredSets \subseteq SUBSET Validators
    /\ transitionCount \in 0..2
    /\ authorized \in BOOLEAN
    /\ phase \in Phases
    /\ proposal \in Values \cup {NoValue}
    /\ certificateEpoch \in {-1, 0, 1, 2}
    /\ certificateSet \subseteq Validators
    /\ durableLock \in Values \cup {NoValue}
    /\ committed \in Seq([epoch : Epochs, value : Values, set : SUBSET Validators])
    /\ online \in BOOLEAN
    /\ crashSnapshot \in Values \cup {NoValue}
    /\ view \in 0..MaxView
    /\ clock \in 0..Deadline
    /\ delivered \in BOOLEAN
    /\ staleRejected \in 0..2

ActiveMembershipIsCurrent == activeSet = Membership[epoch]
TransitionCountMatchesEpoch == transitionCount = epoch
RetiredSetsTrackEpoch ==
    CASE epoch = 0 -> retiredSets = {}
      [] epoch = 1 -> retiredSets = {Set0}
      [] OTHER -> retiredSets = {Set0, Set1}
RetiredCannotCertify == certificateSet = {} \/ certificateSet = activeSet
CertificateBindsEpochAndSet ==
    phase \in {"certified", "committed"} =>
        /\ certificateEpoch = epoch
        /\ certificateSet = Membership[epoch]
        /\ durableLock = proposal
CrashPreservesLock == ~online => crashSnapshot = durableLock
AuthorizedActivationFollowsCommit == authorized => phase = "committed"
CommittedEntriesBindMembership ==
    \A i \in 1..Len(committed) : committed[i].set = Membership[committed[i].epoch]
CommittedPrefixAgreement ==
    \A i, j \in 1..Len(committed) : committed[i].value = committed[j].value
MembershipActuallyChurns ==
    /\ Set0 \ Set1 = {V4}
    /\ Set1 \ Set0 = {V5}
    /\ Set1 \ Set2 = {V3}
    /\ Set2 \ Set1 = {V6}
ASSUME MembershipActuallyChurns
AllTransitionsEventuallyCommit == <> (transitionCount = 2 /\ phase = "committed")

=============================================================================
