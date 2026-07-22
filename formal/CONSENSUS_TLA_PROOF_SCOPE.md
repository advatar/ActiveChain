# ActiveChain cross-round consensus TLA+ proof scope

Status: exhaustively model-checked bounded safety model; not a refinement proof of the Rust node and
not whole-protocol certification.

`formal/tla/ActiveChainConsensus.tla` is the first executable TLA+ model of ActiveChain's
chain-prefix finality kernel. It addresses the cross-round composition left outside the finite
Tamarin model: parent/QC binding, durable locked-QC voting, view changes, Byzantine equivocation,
two-QC commit, crash/restart, and a single validator-set-root transition.

## Checked model and result

The model fixes the following finite universe:

- four equal-weight validators, with three honest identities and one Byzantine identity;
- a strict three-of-four quorum, with the Byzantine validator conservatively available on every
  candidate block;
- five globally ordered rounds containing conflicting same-height candidates and descendants on
  both forks;
- an honest durable vote table with one entry per validator and round;
- an honest durable locked QC, and a safe-vote rule that accepts a block only when it extends that
  lock or its parent QC is strictly newer;
- explicit crash and restart actions that preserve the vote table, view, and locked QC;
- a two-QC consecutive-round commit rule; and
- two distinct validator-set roots with one old-set-committed activation checkpoint. The
  four validator identities are unchanged across that bounded transition.

Using TLA+ tools v1.8.0, TLC completed exhaustive breadth-first exploration with no invariant
violation:

```text
4,465,652 states generated
936,652 distinct states found
0 states left on queue
complete-state-graph depth 32
```

The checked invariants are:

- every durable vote is stored in its block's round;
- every honest durable lock names a certified block;
- an offline validator's persisted lock equals its crash snapshot;
- every certified block binds its direct parent QC, increasing height and round;
- two different blocks cannot both obtain a QC in one round;
- two different committed blocks cannot occupy one height;
- every pair of committed blocks is prefix-comparable;
- epoch one cannot activate before the old set commits the activation checkpoint; and
- every epoch-one certificate extends that checkpoint.

The run is reproducible with:

```sh
bash scripts/check-tla-consensus.sh
```

The runner pins the TLA+ tools v1.8.0 jar by SHA-256
`cc4803dce2a8ffaf0f5920a9dc39df4b5ee34ab4cb53fb58ac557277a7e516b3` and executes it with
Eclipse Temurin 21.0.8 using OCI image digest
`sha256:db1689535962d757a5adabf57387584ed543d38c0b9d1fe870123ea362ad73b0`. The repository does not
depend on an unpinned host Java installation.

## Safety semantics

The candidate's direct parent is also its justifying QC. An honest validator votes only once in a
round and only if the proposal extends its durable lock or carries a parent QC from a strictly
newer round. When voting, it advances the durable lock to that parent QC. A certified child in the
immediately following round commits its certified parent and all ancestors. TLC explores arbitrary
interleavings of voting, view advancement, crashes, restarts, QC emergence, and activation.

The Byzantine validator has no vote lock and is treated as signing every candidate. This is the
worst case for safety in the bounded equal-weight model. Cryptographic forgery by the adversary is
not modeled: honest validator identities cannot be forged, which is the symbolic authentication
premise provided separately by the Tamarin model and ML-DSA implementation/review.

## Rust conformance contract

The TLA+ variables and guards require concrete Rust behavior at these boundaries:

| TLA+ element | Required Rust conformance |
| --- | --- |
| `voteAt[v][round]` | Persist one vote digest for every `(genesis, epoch, validator-set root, protocol revision, height, round)` before releasing an ML-DSA signature; allow only idempotent re-signing of that digest after restart. |
| `durableLock[v]` | Persist the highest locked QC atomically and restore it before processing or signing a proposal. A snapshot that omits or rolls back the lock cannot resume signing. |
| `ProposalParentBound` | A proposal must encode and authenticate its parent block and justifying QC; verification must prove the QC certifies that exact parent and that height/round/domain fields match. |
| `SafeToVote` | The runtime must implement the identical ancestry-or-strictly-newer-parent-QC guard, using checked round ordering and an authenticated ancestry relation. |
| `HasQC` | Count distinct active validators from one immutable validator-set snapshot, verify every domain-separated ML-DSA vote, reject duplicates, and enforce `3 * signer_stake > 2 * total_stake` without overflow. |
| `CommitHeads` | The production commit rule must match the modeled consecutive two-QC rule or receive a separate model for every additional Jolteon/Ditto fast/fallback path. |
| `Crash` / `Restart` | Vote records, current view, lock, finalized head, replay high-water marks, epoch, set root, and revision must share an atomic recoverable snapshot or a proven write-ahead protocol. |
| `ActivateNewValidatorSet` | Activation must be authorized by a block finalized by the old set, bind the next root, and preserve the activation checkpoint as the ancestor of every new-set certificate. The production exact-height rule is an additional obligation modeled in `EpochUpgrade.lean`, not in this TLA+ run. |

Rust `BlockProposal` schema version 2 signs proposer, epoch, height, round, digest, and the complete
parent QC. The runtime admits a chained proposal only when that QC is the highest locally verified
certificate, has the active genesis/epoch/root/revision domain, and certifies the immediately prior
height. It persists both the highest verified QC and highest locked QC in the same atomic validator
safety snapshot as replay and per-slot vote records. A child QC commits its certified parent; an
unchained proposal is accepted only at the first height after genesis or an activated consensus
context. This deliberately linear production rule is a conservative refinement of the model's
ancestry-or-newer-QC safe-vote guard and consecutive two-QC commit rule.

## Explicit assumptions and exclusions

- The model is finite and equal-weight. Arbitrary stake arithmetic is proved separately in Lean,
  but a refinement from concrete signer sets and checked `u128` arithmetic remains required.
- The transition changes the validator-set root but retains the same four identities. Membership
  churn, overlapping-set bounds, key replacement, and multiple consecutive reconfigurations are
  not covered by this run.
- The block graph is bounded to five rounds and four heights. Exhaustive means every state in that
  finite model, not every possible production execution.
- ML-DSA unforgeability, hash collision resistance, canonical decoding, key erasure, storage media
  durability, and compiler/hardware correctness are assumptions outside TLA+.
- The global round order abstracts checked `u64` arithmetic and authenticated timeout/view-change
  certificates. Overflow and malformed timeout certificates require concrete tests and proofs.
- The model treats a formed QC as globally usable; message buffers, partial QC dissemination,
  network framing, data availability, execution validity, and state roots are outside this model.
- Ditto-style asynchronous fallback is not modeled. It may not be enabled under this proof until
  its commit and lock transitions are added and the same invariants are rechecked.

## Fairness and liveness

`Spec` contains no weak fairness, strong fairness, synchrony, delivery, or honest-leader assumption.
TLC checks safety over unfair schedules as well as fair ones. Validators may remain crashed,
messages and votes may be delayed forever, view advancement may be starved, and the system may
deadlock after the finite view bound. `CHECK_DEADLOCK FALSE` acknowledges those expected bounded
terminal states. This artifact proves no termination, responsiveness, finality latency, or eventual
commit. A separate timed/fair liveness model is required before making liveness claims.
