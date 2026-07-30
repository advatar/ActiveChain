# P-070: Bounded validator storage, retention, and archives

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/398>

## 1. Scope

This revision fixes the first storage-capacity contract for ordinary validators. It separates
consensus-visible logical charging from release qualification of physical database use and defines
the evidence required before finalized material may leave validator hot storage.

Archive payments, collateral amounts, concrete database engines, and production snapshot wire
types remain later refinements. Implementations MUST NOT treat filesystem allocation, compression,
or database iteration as consensus input.

## 2. Version-1 qualification profile

Every release that activates this profile MUST qualify a sustained representative workload within
one tebibyte of physical validator storage, including compaction peaks and recovery headroom:

| Class | Budget |
|---|---:|
| Active authenticated state | 512 GiB |
| Assigned hot ledger and DA history | 256 GiB |
| Two complete snapshot generations and deltas | 128 GiB |
| Consensus metadata and indexes | 64 GiB |
| Operational reserve | 64 GiB |

The physical partitions sum exactly to 1 TiB. They are release gates, not values read by consensus.
`testing/storage-profile-v1.tsv` is the machine-readable profile.

## 3. Deterministic charged bytes

Version 1 charges an active object's canonical envelope conservatively:

```text
charged_object_bytes = canonical_object_bytes * 2 + 1,024
```

All arithmetic is checked unsigned arithmetic. Overflow rejects admission. A later protocol
revision may recalibrate this schedule after independent-client and database-amplification
measurements; it MUST NOT reinterpret charges settled under an earlier revision.

At each epoch boundary, utilization is classified in basis points of the logical active-state
budget:

| Utilization | Required behavior |
|---|---|
| below 70% | normal price adjustment |
| 70% to below 85% | elevated state-rent and DA pricing |
| 85% to below 90% | high pricing and increased minimum lease deposits |
| 90% to below 95% | capacity increases prohibited |
| 95% and above | reject non-system net state expansion |

State-reducing deletion and hibernation remain admissible at critical pressure. Transfers and
renewals are admissible only when they do not increase charged active state. Only bounded principal
recovery anchors and base-asset ownership commitments may use an endowment-funded storage class.

## 4. Hot retention and snapshots

Validators retain reconstructable assigned transaction, receipt, witness, and DA material for a
target of 30 days, encoded as an exact epoch count once epoch timing is frozen. They also retain the
current and immediately previous complete certified snapshot.

The production snapshot profile MUST provide partition deltas for every finalized block,
incremental snapshots at least hourly, a full certified snapshot at least daily, and 4,096
partitions selected by the P-031 partition identifier. A manifest binds chain genesis, height,
protocol revision, global state root, partition roots, chunk roots, and charged-byte totals.

Wall-clock targets are operational requirements until the epoch-duration contract is frozen. A
node MUST use finalized heights and epochs, not its local clock, for protocol eligibility.

## 5. Archive durability

Archive segments are content-addressed and erasure-coded into twelve provider assignments. Any
eight valid shards MUST reconstruct the segment. Assignments MUST cover at least four declared
compound failure domains, and no failure domain may receive more than three shards.

An archive certificate commits chain genesis, content root, data class, canonical length, covered
heights, coding profile, provider assignments, failure-domain declarations, retention expiry, and
signed custody receipts. Receipts authorize payment eligibility but do not alone prove continuing
possession. Providers answer unpredictable authenticated retrieval challenges during the paid
term. Objective missing or invalid responses withhold payment and permit reassignment.

Provider admission and shard service MUST remain permissionless. Serving one assigned shard MUST
not require possession of the complete historical ledger.

## 6. Pruning safety

A segment becomes prune-eligible only when all conditions hold:

1. it is finalized and included in the permanent checkpoint/history commitment;
2. it is older than the mandatory hot-retention window;
3. two newer complete certified snapshots are durable;
4. all applicable proof and dispute grace periods elapsed;
5. an unexpired archive certificate satisfies the active coding and diversity profile; and
6. the pruning watermark can be persisted atomically before deletion.

The watermark MUST never advance beyond the weakest durable prerequisite. Restart repeats deletion
idempotently. Snapshot or archive failure blocks pruning, not finality. Archive nodes MAY disable
deletion while still publishing the same commitments and certificates.

## 7. Hibernation and restoration

Ordinary objects prepay active leases. After expiry, an object becomes immutable while its canonical
value is assigned to prepaid renewable cold retention. Only after archive certification may active
state replace it with a compact hibernation record committing the object identity and version,
type, owner commitment, value and policy roots, hibernation epoch, archive root, and retention
expiry.

The compact commitment remains after cold retention expires. Restoration supplies the exact
canonical value and commitment proofs, preserves identity and version semantics, and prepays a new
active lease. Network retrieval is guaranteed only through the prepaid cold term; an owner-held
copy remains independently usable afterward.

## 8. Replay and historical state

Nullifiers, spent-input barriers, revocations, and retired validator history MUST NOT be deleted
merely because their source segments are old. Material may be pruned only after an authenticated
accumulator preserves its security semantics and every admitted transition verifies a witness
against the exact current root.

Validators may retain recent finalized headers plus epoch checkpoint accumulator state. Archive
proofs make older headers permanently verifiable without requiring every validator to store every
header body.

## 9. Required properties

```text
logical accounting is deterministic and overflow-safe
physical qualification partitions sum to exactly 1 TiB
any eight valid archive shards reconstruct the committed bytes
archive corruption or substitution fails commitment verification
pruning never precedes durable snapshot and archive evidence
hibernation and restoration preserve committed object semantics
replay rejection survives pruning of source history
checkpoint plus snapshot plus deltas reproduces the finalized state root
```

Capacity increases MUST fail their release gate when the qualified p95 validator exceeds 1 TiB,
the hot window is incomplete, archive reconstruction falls below eight valid assignments, or the
required failure-domain diversity is absent.
