The architecture can scale without forcing every node to become a data center, but that outcome is not yet fully implemented or specified. The design has the
  right separation—active state, recent data availability, permanent commitments, and paid archives—but today it is more of a scalability plan than a
  demonstrated storage system.

  The crucial distinction should be between four node roles:

   Node role            Data responsibility
  ━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Light verifier       Headers, validator sets, checkpoints, selected proofs; likely MB–low GB
  ───────────────────  ──────────────────────────────────────────────────────────────────────────────────
   Pruned validator     Current authenticated state, two snapshots, recent deltas, assigned DA retention
  ───────────────────  ──────────────────────────────────────────────────────────────────────────────────
   Full node/indexer    Current state plus query indexes and configurable history
  ───────────────────  ──────────────────────────────────────────────────────────────────────────────────
   Archive provider     Historical blocks, witnesses, snapshots, and DA batches; potentially many TB/PB

  ### How much data might a validator manage?

  There is no workload or throughput target precise enough to give a single reliable number. We can establish useful bounds:

  - An object is bounded at about 16.9 KB, although normal objects should be much smaller. spec/protocol/P-030-object-model.md:123
  - The DA prototype uses 4 MiB source batches expanded to 16 MiB after erasure coding. BLUEPRINT.md:1536
  - Transaction and witness retention is proposed as 30 days, with only the current and previous complete snapshots mandatory. BLUEPRINT.md:1586
  - The present validator target is already fairly substantial: 16 cores, 64 GB RAM, 2 TB NVMe, and 100 Mbps. DECENTRALIZATION.md:269

  Illustrative DA growth, assuming one 4 MiB source batch per second:

  - Source data: roughly 346 GB/day or 10.4 TB/30 days.
  - Fully encoded data: roughly 1.38 TB/day or 41.5 TB/30 days.

  A normal validator therefore cannot retain every encoded share at sustained high throughput. It must store only an assigned fraction, sample the rest, and rely
  on multiple independently selected retention providers.

  For active state, worst-case raw object data would be approximately:

  - 1 million maximum-size objects: 16.9 GB.
  - 10 million: 169 GB.
  - 100 million: 1.69 TB.

  Tree nodes, RocksDB amplification, indexes, snapshots, and compaction could make physical storage roughly 2–4 times the raw live-object size. Conversely, if
  the typical object is 0.5–2 KB, the practical numbers are dramatically lower. The project needs realistic workload distributions before selecting a safe state-
  capacity limit.

  ### Can the system prune?

  Yes. The intended design already contains most of the right mechanisms:

  - Finalized ledger history goes into immutable segment files, separate from active RocksDB state.
  - Incremental snapshots are proposed hourly, certified full snapshots daily, with two complete generations retained hot.
  - Old blocks, deltas, receipts, witnesses, and DA data can move to content-addressed S3-compatible storage.
  - Archive providers may use local disks, cloud storage, erasure-coded storage, or tape. STACK.md:1318
  - Expired objects are intended to hibernate: their complete values leave the active database, while a small committed record remains. Owners can later restore
    them using the old value and a renewed lease. BLUEPRINT.md:1038

  - Headers, state roots, and validator-transition commitments remain permanent, allowing cold data to be authenticated after retrieval.

  A safe pruning rule would be approximately:

  1. Finalize a block and its execution/DA commitments.
  2. Produce and certify a newer full snapshot.
  3. Keep two certified snapshot generations locally.
  4. Verify that historical material has reached the required number of independent archive providers.
  5. Delete local blocks, witnesses, deltas, and DA shares older than the protocol retention window.
  6. Retain permanent headers, roots, validator-set history, archive manifests, and any replay-prevention state that cannot yet be represented by an accumulator.

  Nullifiers, spent-coin information, nonces, validator-set history, and authorization revocation data must not simply be deleted. They need either bounded
  expiry rules or cryptographic accumulators with provable state transitions.

  ### What is missing?

  The biggest weakness is that pruning is not yet a frozen protocol contract.

  spec/protocol/P-031-state-tree.md:1 is still Draft 0.1 and explicitly places persistence, leases, hibernation, snapshots, deltas, and state sync outside its
  current scope. The implemented development validator snapshots also remain much smaller and simpler than the intended global state system; the status file
  notes that current consensus snapshots contain metadata only in an important wallet path. STATUS.md:1941

  Before claiming broad scalability, I would require a normative storage specification covering:

  - Exact retention periods and whether they vary by data class.
  - Maximum validator-assigned DA storage and bandwidth per epoch.
  - Minimum archive replication across independently controlled providers.
  - Proof-of-retention and random retrieval challenges.
  - Snapshot certification, availability, and deletion preconditions.
  - Hibernation-record size and resurrection rules.
  - Accumulator treatment for nullifiers and other permanent negative state.
  - State-rent pricing that tracks measured disk and replication costs.
  - A hard target for operation on consumer-grade hardware.

  ### Avoiding a big-player-only network

  The most important policy is to cap the mandatory validator working set. Throughput must not silently increase the disk requirement forever.

  I would set an explicit design objective such as:

  - Pruned validator: at most 1–2 TB of protocol-required storage.
  - Community validator: ordinary workstation/server, no GPU requirement.
  - Light verifier: laptop or phone-class storage.
  - Archive and proving roles: permissionless, paid, and non-authoritative.
  - No validator required to retain every DA share or historical witness.
  - State rent and hibernation activated before unbounded state growth is possible.

  So the bottom line is: verification scalability looks promising; historical-storage scalability is architecturally plausible; active-state scalability still
  needs enforceable bounds. Without the pruning, hibernation, archive-market, and accumulator rules becoming normative and tested, the proposed 2 TB validator
  target will eventually be exceeded and validator participation will concentrate among large operators.
