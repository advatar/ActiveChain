# Reconfiguration and timed-liveness TLA+ proof scope

`ActiveChainReconfiguration.tla` is a finite, executable model of the launch
protocol's membership-transition boundary. It complements, rather than
replaces, the larger fixed-membership safety exploration in
`ActiveChainConsensus.tla`.

## Checked claims

- The active membership is exactly the set bound to the current epoch through
  two transitions: `{V1,V2,V3,V4}` to `{V1,V2,V3,V5}` to
  `{V1,V2,V5,V6}`.
- Each activation follows a committed authorization, increments the epoch
  exactly once, retires the old set, and admits the scheduled joiner while
  removing the scheduled leaver.
- A certificate is accepted only for the exact current epoch and active set.
  A retired-set certificate can only take the rejection transition and cannot
  change a lock, certificate, commit, or membership.
- The durable lock and its crash snapshot agree while the node is offline;
  restart does not discard the lock, certificate, or committed history.
- Under the liveness assumptions below, both membership transitions and a
  commit in the final epoch eventually occur.

## Liveness assumptions

The liveness configuration disables crashes. The finite clock reaches a
deadline, timed-out views rotate leaders, and every third view has an honest
leader. Delivery becomes enabled after `NetworkDelay`. Weak fairness is
declared separately for clock ticks, delivery, timeouts, honest proposals,
certification, commit, authorization, and activation. Thus the progress result
does not claim progress under permanent partitions, permanent crashes,
unbounded delay, unfair scheduling, or an exhausted finite view range.

## Abstraction boundaries

Quorum formation and signatures are abstracted into the `Certify` action; the
model checks epoch/set admission but assumes cryptographic authenticity and a
correct quorum predicate. It models one durable node state, not a distributed
per-validator vote table. Values are two symbolic alternatives, clocks and
views are bounded, stake weights are equal, transition membership is fixed by
the schedule, and only two transitions are explored. The model is not an
unbounded refinement proof of the Rust implementation and does not establish
production liveness by itself.

The safety configuration permits arbitrary crash/restart points and stale-set
attempts. The liveness configuration intentionally removes those adversarial
actions and adds the stated fairness conditions. Any future counterexample is
a gate failure: retain TLC's trace, minimize it before changing an invariant,
and document any weakened claim in this file and `STATUS.md`.
