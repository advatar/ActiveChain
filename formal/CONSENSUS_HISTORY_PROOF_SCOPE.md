# Finalized-history prefix proof scope

Status: mechanically checked abstract Lean model; not a whole-protocol or Rust refinement proof.

`formal/lean/ActiveChain/ConsensusHistory.lean` models finalized histories as canonical lists from
genesis to tip. Adjacent blocks bind the exact parent digest, advance height once, keep views
monotonic, and either retain the epoch or advance it exactly once. The model proves:

- a consensus-supplied comparable-tip obligation lifts to prefix comparability of the complete
  histories;
- restoring a durable snapshot preserves the exact finalized history and cannot create rollback
  or a fork;
- a first block in a new epoch remains an exact parent-bound extension of the prior history; and
- restart preserves the cross-history prefix result.

## Assumptions and unverified boundary

The critical `FinalizedTipsComparable` premise is supplied by the QC intersection, safe-vote,
durable-lock, view-change, and reconfiguration layers. This module exposes rather than proves that
premise. Existing Lean weighted-quorum and bounded TLA+ models provide component evidence, but an
unbounded trace refinement showing that every production Rust execution establishes the premise
remains open. Cryptographic authenticity, canonical decoding, filesystem durability, compiler
correspondence, liveness, and independent review are also outside this theorem.

Counterexamples or a failure to establish the comparable-tip premise must be treated as a protocol
or implementation defect; they must not be hidden by weakening prefix comparability.
