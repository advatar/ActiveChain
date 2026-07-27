# Transaction monitoring and case management v1

Monitoring is provider-operated and does not expose surveillance data on the public ledger. The
monitor consumes finalized action/receipt streams, reconciles the complete population, and stores
raw alerts and case evidence off-chain.

## Controls

- Every finalized transfer is included exactly once in the monitored population, including failed,
  refunded, and rejected actions where policy requires.
- Rules are versioned and commit to asset, amount, velocity, counterparty, jurisdiction, and
  screening signals. Rule updates have an effective timestamp and cannot rewrite history.
- Alerts are deduplicated by action ID and rule revision. Cases have immutable creation, owner,
  escalation, decision, and closure events.
- Suspicion decisions, freezes, and releases require configured authority and a reason commitment;
  emergency action is time-bounded and reviewable.
- FIU/reporting payloads are transmitted through the regulated provider channel. The chain stores
  only a case/report commitment and finalized action binding.

Population gaps, stale indexers, rule-evaluation failures, and unavailable case systems are
operational incidents; they block regulated-profile admission rather than silently passing.
