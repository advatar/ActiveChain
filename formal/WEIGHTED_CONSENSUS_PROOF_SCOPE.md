# ActiveChain weighted-consensus proof scope

Status: mechanically checked aggregate safety theorem; signer-set and Rust
refinement remain explicit launch obligations.

The Lean module
`formal/lean/ActiveChain/WeightedConsensus.lean` generalizes the finite
four-validator Tamarin model in
`formal/tamarin/activechain_consensus.spthy`. It proves the weighted arithmetic
and composes it with a precisely stated durable-lock premise. It does not claim
that arbitrary Rust data has already been refined into the Lean model.

## Mechanically proved arithmetic

For two signer sets, all validator stake is represented by four exhaustive,
disjoint natural-number aggregates:

- stake only in the first signer set;
- stake only in the second signer set;
- stake in both signer sets; and
- stake in neither signer set.

The aggregates are arbitrary natural numbers. The module uses multiplication
inequalities rather than division or subtraction:

- strict quorum means `2 * total < 3 * quorum`; and
- the Byzantine bound means `3 * byzantine < total`.

Lean proves:

1. if both signer sets are strict two-thirds quorums, then
   `total < 3 * intersection`; and
2. if Byzantine stake is strictly below one third, then
   `byzantine < intersection`.

These results cover arbitrary natural stake distributions and do not depend on
the Tamarin model's four equal-stake validators. Natural numbers also avoid
machine-integer overflow inside the theorem.

## Mechanically proved safety composition

The module represents a consensus slot by chain identity, epoch, validator-set
root, height, and round. Two candidate QCs have the same slot by construction.
It then proves that their digests are equal when all of the following premises
hold:

1. both QCs satisfy the strict weighted quorum inequalities;
2. Byzantine stake satisfies the strict one-third bound;
3. the aggregate intersection refines to concrete, distinct signer identities,
   so intersection stake above the Byzantine budget produces a signer that is
   honest and present in both QCs; and
4. every honest signature in both QCs agrees with one shared durable
   `validator -> slot -> digest` vote-lock table.

The fourth premise captures one-vote-per-slot across process restarts: the lock
is written atomically before signature release and restored before any later
signature can be emitted. Given a common honest signer, both QC digests equal
the same persisted lock value, so conflicting digests are impossible.

## Relationship to Tamarin

The Tamarin model proves a bounded, executable trace version for four
equal-stake validators, one Byzantine validator, explicit three-of-four signer
sets, and linear honest vote rights. Its independently verified lemmas establish
authenticated membership, honest non-equivocation, and honest quorum
intersection for that finite universe. Automated Tamarin search did not finish
the original composed `no_conflicting_qcs_for_one_slot` lemma.

The Lean result closes the missing composition and generalizes the quorum
arithmetic. It does not replace Tamarin's trace/authentication results: Lean
takes the signer-set refinement and lock conformance as premises, while Tamarin
models how signatures and vote rights arise over traces.

## Relationship to Rust

The theorem maps to these implementation responsibilities:

- `protocol-types`: every vote signature and slot key must bind chain/genesis,
  epoch, active validator-set root, height, round, and digest;
- `consensus-runtime`: stake totals and signer totals must be computed from one
  immutable validator snapshot, each signer counted exactly once, and the
  strict check must be equivalent to `3 * signer_stake > 2 * total_stake` with
  checked arithmetic;
- `consensus-runtime`: an honest validator's vote lock must be durably written
  before signing, permit idempotent reuse only for the same digest, and be
  restored before signing after restart; and
- QC verification: every signature must authenticate a distinct active
  validator and the signer-set intersection weight must use the same stake map
  and slot domain as the QC threshold check.

The aggregate-to-signer premise is intentionally not hidden. A conformance
layer still must show that the Rust validator snapshot is unique by validator
identity, that stake addition cannot overflow, that no duplicate signature is
counted twice, and that its computed Venn aggregates equal the Lean partition.

## Out of scope

This module does not prove ML-DSA security, hash collision resistance, storage
hardware durability, liveness, timing, leader selection, data availability,
state-transition validity, validator-set activation, or correctness of the Rust
compiler and platform. It introduces no `axiom`, `sorry`, or `admit` for those
properties. They remain separate cryptographic, protocol, implementation, and
review obligations.
