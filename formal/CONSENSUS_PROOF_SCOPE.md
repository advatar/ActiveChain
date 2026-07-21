# ActiveChain consensus proof scope

Status: development proof model; not whole-protocol certification.

The executable Tamarin model is `formal/tamarin/activechain_consensus.spthy`. It isolates the
consensus safety argument from liveness and from the rest of the ActiveChain state transition. Its
purpose is to make quorum, authentication, replay, equivocation, and finality assumptions explicit
enough to test mechanically and to expose mismatches with the Rust runtime.

## Model boundary

The model uses four equal-stake validators and every QC contains one of the four explicit
three-validator subsets. This is the smallest useful representative of ActiveChain's strict
`signer_stake * 3 > total_stake * 2` rule. Validators `v1`, `v2`, and `v3` are honest; `v4` is the
only compromised validator. Consequently, Byzantine stake is strictly below one third and every
pair of QCs intersects in at least two validators, at least one of which is honest.

The model assumes:

- perfect symbolic signatures and collision-resistant hashing in Tamarin's Dolev-Yao model;
- a fixed active validator set and independently generated epoch keys for each modeled genesis;
- exactly one durable vote right per honest validator, epoch, parent rank, and round;
- authenticated votes are bound to validator, parent rank, round, and block digest;
- admitted peer-envelope sequences are fresh high-water-mark values, while public bytes remain
  replayable by the adversary;
- the local finalized frontier is a linear resource; and
- a successor rank is the free term `next(parent, digest)`, abstracting the Rust lexicographic
  `(height, round)` check as an append-only lineage.

These assumptions are part of the theorem statement. The model does not prove ML-DSA or SHAKE,
availability, execution validity, state roots, economic correctness, timing, leader election,
liveness under partitions, arbitrary weighted-set arithmetic, epoch transitions, or mobile/FFI
behavior.

## Mechanically verified lemmas

Tamarin 1.12.0 completed the following all-traces proofs locally:

- `authenticated_votes_have_registered_signers`
- `accepted_envelope_cannot_be_replayed`
- `honest_validator_does_not_equivocate`
- `qc_has_an_explicit_three_of_four_quorum`
- `qc_members_are_authenticated`
- `strict_quorums_intersect`
- `strict_quorums_share_an_honest_validator`
- `finality_requires_prior_qc`
- `finality_is_monotonic_extension`
- `a_finality_frontier_is_consumed_once`
- `finality_never_immediately_rolls_back`

The finality statements establish that every modeled acceptance has a prior QC, extends the one
linear frontier, cannot consume the same frontier twice, and cannot immediately transition back to
its parent. They do not prove numeric ordering for every `u64` height/round pair or validator-set
changes.

Proofs were run individually to avoid one difficult composition target preventing completion of
the bounded subset:

```sh
tamarin-prover --version
tamarin-prover formal/tamarin/activechain_consensus.spthy \
  --prove=<lemma-name> --derivcheck-timeout=0
```

Each named proof above returned exit status 0 and `verified`. Representative proof-search sizes
were 32 steps for signer registration, 151 for replay rejection, 62 for honest non-equivocation,
134 for authenticated QC membership, 76 for honest quorum intersection, and two to six steps for
the direct finality properties.

## Incomplete composition target

`no_conflicting_qcs_for_one_slot` is present as the intended composed theorem. Its prerequisites
are independently verified: strict quorums share an honest validator, and an honest validator does
not equivocate. Automated proof search for the composition remained incomplete and was terminated
after exceeding the bounded local run window; Tamarin produced neither a proof nor a
counterexample. It must therefore remain explicitly **unproved** until a source lemma/oracle or a
smaller compositional model closes it. The component lemmas are not a substitute for that proof.

The equal-stake four-validator proof must also be generalized to arbitrary bounded weighted sets,
or connected to a separately checked arithmetic theorem proving that two strict two-thirds quorums
have honest intersection whenever Byzantine stake is below one third.

## Rust conformance gaps discovered by the model

The model is conditional and is currently stronger than the implementation in three
launch-critical places:

1. `ValidatorEngine` does not persist a one-vote-per-`(chain, epoch, height, round)` lock.
   Replacing its current proposal can allow the same local signer to sign different digests for the
   same slot. A vote lock must be written durably before emitting a signature, permit idempotent
   re-signing only for the same digest, and be restored before signing after restart.
2. `ValidatorVote::signing_payload` binds validator, height, round, and digest, but not an immutable
   chain/genesis identity, epoch, or active validator-set root. Cross-network and cross-epoch domain
   separation therefore remains an implementation obligation.
3. `ReplayGuard` stores `sender -> highest_sequence` only in memory. Restart resets the guard, and
   peer-envelope signatures do not bind a fresh authenticated session identifier. Replay high-water
   marks must be persisted atomically with recoverable consensus state, or envelopes must bind a
   chain-scoped, unforgeable session identifier with a formally modeled reset rule.

Until those gaps are implemented and tested, these Tamarin results must not be described as a proof
of the deployed consensus runtime. A later conformance layer should generate Rust traces/vectors
for vote locking, chain/epoch binding, replay across restart, QC formation, and snapshot recovery
and check them against this model's event vocabulary.
