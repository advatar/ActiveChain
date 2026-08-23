# Public authorized-transfer submission v1

This document describes the developmental ordinary-transfer ingress implemented by RPC schema
revision 4. It does not claim that the currently deployed Kanalen endpoint has been upgraded; use
the network status response and the Kanalen onboarding guide for the deployed revision.

## Wire contract

`SubmitAuthorizedTransfer` is `RpcRequest` tag 13. It carries the canonical envelopes for one
`AuthorizedCashSessionGrantV1` and one `AuthorizedCashTransferV1` as separate byte strings, each
bounded to 24 KiB. `ResolveTransfer` is request tag 14 and carries the transfer request's
`intent_id()`.

An accepted submission returns `TransferReceipt` at `RpcResponse` tag 11. A refusal before durable
admission returns `TransferRejected` at response tag 12 and creates no resolvable state. The
request-envelope schema is 3, the response-envelope schema is 4, and `RpcStatus` advertises global
RPC schema revision 4.

The intent identifier is the transaction, receipt, and deduplication key. During receipt retention,
the first authenticated bundle durably accepted for an intent fixes its session authorization
context. A duplicate returns that existing receipt before quotas or spool capacity are consulted.

## Lifecycle and limits

Admission checks bounds and canonical encoding before authentication. It then cross-checks chain,
signer, and session identity, verifies both signatures against the finalized wallet ingress, and
applies signer, global, pending-count, and pending-byte limits. Only then does one authenticated,
crash-atomic snapshot publish both the exact bundle and its `Pending` receipt.

The journal permits only `Pending → Finalized | Rejected`. A retained terminal receipt never
regresses and a duplicate never re-enqueues it. Terminal receipts expire after the configured
retention; resolution then returns an explicit `Unknown` receipt. Snapshot updates are serialized
with an OS file lock and reload the latest authenticated snapshot while holding that lock, so the
RPC process and round assembler cannot lose each other's updates. Locks are released by the OS if a
process exits.

The journal has hard implementation ceilings of 32 pending transfers, 1,024 retained records, and
a 64 MiB authenticated snapshot. Deployment settings may choose lower limits.

## Round and finality boundary

`activechain-transfer-spool prepare` loads the exact finalized RPC identity and cash-ingress
snapshot, revalidates pending bundles in accepted order, and appends at most 32 total cash actions
to the round batch. A bundle invalidated after admission receives a durable terminal rejection
before the batch is published.

The validator commits transaction intent identifiers into `cash_action_root` and archives both the
accepted cash-action batch and finality bundle. `activechain-transfer-spool reconcile-latest` (and
the RPC node's recovery scan) verifies the pinned genesis and exact action root before changing a
matching receipt to `Finalized` with its transaction, height, and block identifier.

## Operator configuration

Providing `ACTIVECHAIN_TRANSFER_SNAPSHOT` enables the transfer journal configuration boundary and
requires `ACTIVECHAIN_WALLET_INGRESS_SNAPSHOT`. The following settings are then mandatory:

- `ACTIVECHAIN_TRANSFER_ENABLED`
- `ACTIVECHAIN_TRANSFER_MAX_PENDING_COUNT`
- `ACTIVECHAIN_TRANSFER_MAX_PENDING_BYTES`
- `ACTIVECHAIN_TRANSFER_MAX_RETAINED_RECORDS`
- `ACTIVECHAIN_TRANSFER_RETENTION_SECONDS`
- `ACTIVECHAIN_TRANSFER_SIGNER_WINDOW` and `ACTIVECHAIN_TRANSFER_SIGNER_LIMIT`
- `ACTIVECHAIN_TRANSFER_GLOBAL_WINDOW` and `ACTIVECHAIN_TRANSFER_GLOBAL_LIMIT`
- `ACTIVECHAIN_TRANSFER_FINALITY_ARCHIVE_DIR`

The checked-in Kanalen launch agent uses 16 pending bundles, 768 KiB pending bytes, 1,024 retained
records, seven days of terminal retention, four submissions per signer per 60 seconds, and 32
global submissions per 60 seconds.

## Rollout

RPC revision 4 is fail-closed and must be coordinated:

1. qualify one exact release candidate containing the node, transfer spool binary, round script,
   probe, canonical vectors, and revision-4 wallet pins;
2. install the node release first, while clients still refuse the new advertised revision;
3. verify the TLS status reports protocol revision 1, RPC schema revision 4, the expected chain and
   genesis, and an advancing healthy finalized height;
4. distribute the revision-4 wallets second;
5. submit a signed session-plus-transfer bundle, observe `Pending`, complete a round, and require
   the same intent to resolve as `Finalized` before declaring the rollout complete.

Rollback must keep the node and wallet compatibility boundary explicit. A revision-3 wallet must
refuse a revision-4 node; operators must not relabel one wire shape as another.
