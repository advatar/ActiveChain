# P-098: External credential status anchors

## 1. Authority boundary

An external issuer's status mechanism remains authoritative. ActiveChain records a finalized,
authenticated snapshot commitment; it does not create an independent revocation opinion. Raw
credential identifiers, subject identifiers, claims, status lists, and issuance logs MUST remain
off-chain.

## 2. Publisher governance

`ExternalStatusPublisherSetV1` binds an external issuer to a sorted, bounded updater set, approval
threshold, generation, activation interval, previous-set commitment, and governance authorization.
The consensus transition MUST verify the authorization evidence satisfies that threshold; the
canonical type records the verified result and rejects an updater outside the active set.

Publisher-set successors preserve the issuer, increment generation by one, and commit the exact
previous set. Operators MUST retain authorization evidence and publish monitoring, outage,
key-recovery, and equivocation-response procedures.

## 3. Snapshot identity and ordering

`ExternalCredentialStatusSnapshotV1` binds chain and genesis, issuer binding, credential profile
and schema, status mechanism/version/source identifier, status root, sequence, observation time,
anchor and freshness heights, exact predecessor, updater and publisher set, update authorization,
optional issuance-transparency root, and lifecycle state.

Each `(chain, genesis, issuer, profile, schema)` slot begins at sequence 1. Successors increment by
one, advance source observation and finalized anchor height, and commit the exact predecessor.
Changing the mechanism, version, or source identifier is valid only in `SourceMigrated` state.
Competing successors are equivocation and MUST fail before state commitment.

## 4. Finality and policy

`ExternalCredentialStatusRegistryV1` stores at most one current snapshot per slot. Applying a
snapshot requires a strictly increasing finalized height equal to the snapshot anchor, the exact
active publisher-set commitment, and an authorized updater. Restart decoding revalidates sorted,
bounded canonical state.

A verifier MUST reject a snapshot when the query height is not finalized, is outside its validity
interval, exceeds policy `maximum_root_age`, is suspended, or lacks an issuance-transparency root
when policy requires one. Missing or unavailable status is not evidence of good standing.

## 5. Proof-bearing and offline verification

A proof-bearing query identifies the slot and returns the canonical snapshot plus state-membership
and finality evidence. The verifier authenticates that evidence through the normal ActiveChain
state-proof path, then checks `binds_evidence` against the exact external status root and optional
issuance-log root used by the presentation adapter. Receipts MUST retain the snapshot commitment,
finalized height, policy parameters, and external proof inputs needed to repeat those checks
offline.

## 6. Failure behavior

Implementations fail closed on wrong chain/genesis, issuer/profile/schema substitution, stale or
missing roots, rollback, skipped sequence, predecessor mismatch, unauthorized updater, publisher
set mismatch, ambiguous source migration, suspended sources, required-log absence, and source
outage beyond policy grace. Recovery is a new governed publisher set or a monotonic snapshot; it
never rewrites accepted history.
