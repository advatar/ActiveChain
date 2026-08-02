# ActiveBridge deterministic recovery drill v1

Run the package-scoped rehearsal from the repository root:

```sh
scripts/rehearse-activebridge-recovery.sh
```

The command runs thirteen named, serial tests over the production nTZS attempt journal and complete
payment settlement aggregate. A successful result establishes that:

- exact request preparation is idempotent while changed retries conflict;
- a crash after provider dispatch remains ambiguous and forces reconciliation after restart;
- intent, idempotency binding, and lifecycle state persist as one exact successor;
- verified settlement and initialized refund accounting survive restart together;
- refund and dispute substitutions or replays fail closed;
- failed treasury, API replay, and fee-sponsorship writes consume neither budget nor nonce;
- webhook cursors require a retained intent and survive restart without accepting replay; and
- a 64-intent workload preserves exact retries, lifecycle and webhook state across eight periodic
  complete-aggregate process reopens; and
- a complete finalized refund cannot exist without its settlement-bound cumulative accounting.

The script exits on the first failure and emits a versioned JSON success record only after every
named test executes successfully. `--exact` prevents a renamed or missing scenario from silently
passing through a broader filter, and `--test-threads=1` preserves deterministic filesystem use.

This is a developmental local recovery drill. It does not exercise a live provider, regulated
asset, production secret manager, multi-process soak, real network partition, operator paging,
backup restoration, external audit, or staged pilot. Those remain separate rollout gates and no
provider observation is promoted to ActiveChain finality by this rehearsal.

## Time-based multi-process chaos

Run the separate process-level rehearsal with a duration and worker count:

```sh
scripts/rehearse-activebridge-multiprocess-chaos.sh 30 1
```

The runner builds the connector-host test executable once and then invokes it directly from four
independent worker modes. This avoids overlapping Cargo builds while continuously exercising:

- 64-intent aggregate load, periodic restart, and exact snapshot comparison;
- provider rejection, reversal, and unknown-state behavior as an outage boundary;
- invalid terminal edges and reordered provider sequences as a partition/reordering boundary; and
- partial-state and failed atomic-write rejection under repeated write pressure.

Every process must complete at least one full iteration and exit successfully. The command emits a
versioned JSON record containing the duration, process count, and aggregate iteration count only
after all workers pass.

This remains deterministic simulator evidence. It does not impose kernel-level memory, disk, or
file-descriptor exhaustion; interrupt real sockets; contact a live provider; page an operator; or
satisfy independent review and staged-pilot requirements.
