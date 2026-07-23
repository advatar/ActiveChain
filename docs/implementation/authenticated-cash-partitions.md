# Authenticated cash partition roots

Cash state partitions use the same canonical mapping as `PartitionedCashPlan`: the first two bytes
of the Coin Cell identifier, interpreted big-endian, modulo the configured partition count. The v1
implementation accepts 1 through 256 partitions.

Each partition is represented by the existing 384-level authenticated Coin Cell root, including
its local record count. Empty partitions reuse the canonical empty-set root. The global partition
root is SHAKE256/384 over a distinct authenticated-cash transcript kind containing the partition
count and every `(index, partition_root)` pair in ascending index order. It therefore binds empty
partitions, ordering, and the configured count rather than treating the roots as an unordered set.

`AuthenticatedCoinCellPartitionRoots` is canonical and fail-closed: decoding requires exactly one
root per declared partition and recomputes the global root. Tests cover the production mapping,
single-partition mutation locality, count and order binding, round trips, invalid counts, and global
root substitution.

`CoinCellPartitionTransitionWitness` carries the complete ordered pre-root vector and a strictly
sorted list of local transitions for exactly the partitions changed by a state transition. Each
nested mutation must map to its declared partition. Verification checks every sparse transition,
replaces only its declared pre-root, and recomputes both global roots. Empty transitions, duplicate
or out-of-order partitions, substituted roots, wrong-partition records, and malformed canonical
encodings fail closed.

This completes the canonical witness foundation for issue #76. The remaining work is to carry these
witnesses through each accepted CashAIR row and constrain their ordered global transition.
