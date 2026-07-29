# P-132 — Validity-proof liveness policy

Status: normative liveness policy for the v1 protocol family.

Validity proofs improve independent verification but must not turn a concentrated proving market
into an undisclosed liveness dependency. ActiveChain therefore separates proof validity from block
availability and defines an explicit degraded mode.

## Normal mode

Validators may finalize a block only when its canonical execution has passed validator
re-execution and the block carries a proof receipt satisfying the active proof profile. Proof
receipts are bound to the exact protocol revision, pre-state root, post-state root, and transition
commitment. A proof from another revision or state is not a usable substitute.

## Grace period and fallback

If no valid proof is available before the proof deadline, validators may continue a bounded
re-execution-only grace period. During the grace period:

- validators still execute and independently check the transition;
- the block is marked proof-pending and cannot trigger proof-dependent upgrades or rewards;
- the maximum grace depth is fixed in the active protocol profile;
- a later proof must bind to the same finalized execution commitment.

If the grace depth is exhausted, the chain enters a liveness halt for that lane rather than
accepting an unverified transition. Already-finalized history remains valid and replayable.

## Recovery

The chain resumes normal mode only after a proof satisfying the active profile is available and
the recovery block includes a deterministic proof-availability receipt. Recovery cannot rewrite or
skip proof-pending history. Operators may rotate among registered proving implementations, but
they cannot lower the security floor or substitute a self-attestation.

## Decentralisation accounting

Metrics MUST report validity concentration and liveness concentration separately. A single prover
may be unable to corrupt state validity, yet still delay the chain; that delay is a liveness risk
and must be included in the release scorecard and operational monitoring.
