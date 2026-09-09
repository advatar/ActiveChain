# Faucet settlement and recovery

Issues [#839](https://github.com/advatar/ActiveChain/issues/839) and
[#841](https://github.com/advatar/ActiveChain/issues/841) track the Kanalen incident and repair.

Each grant promises two Coin Cells whose amounts sum to the advertised grant amount.
The built-in signer reconstructs pending treasury reservations from the durable signed
settlement journal over the authoritative finalized cash snapshot. This reserves successive
nonces and the actual input/change cells across requests and process restarts. It never
changes the consensus snapshot while preparing a signature. Expired authorizations cannot
reserve future spending; unexpired conflicting reservations fail closed.

Spool filenames begin with a fixed-width nonce. The round runner takes at most 32 members,
recovers interrupted moves, and qualifies each batch against finalized cash state before
submitting it to validators. Qualification orders dependencies and durably quarantines exact
invalid bytes before replacing the active batch. Existing batches are qualified on retry.
Quarantine does not mark a receipt paid or authorize a replacement transfer.

Faucet snapshot version 4 persists the confirmed transaction identities for each grant.
Version 1–3 records remain readable; pending records acquire no invented confirmations.
RPC reconciliation verifies native finality and the complete ordered cash-action commitment,
and replays archives in height order. A grant becomes finalized only after every promised
cell appears in verified finalized batches, including across blocks and restarts.

## Expired, unexecuted grant

Use a qualified release containing `activechain-faucet-recover-expired`. First pause new
admissions and stop RPC and the round runner; wait until the current round has completed.
Back up the faucet snapshot, settlement journal, cash ledger, RPC index, finality bundle,
pending batch and spool, and installed RPC plist into a private incident directory.

Run the following against the deployment's authoritative, mutually consistent snapshots:

```sh
current/bin/activechain-faucet-recover-expired \
  rpc/faucet.snapshot rpc/faucet-settlement.journal \
  chain/cash-ledger.snapshot rpc/rpc-index.snapshot chain/finality.bundle \
  <96-character-grant-reference>
```

The command verifies the pinned native certificate, chain, exact finalized height and cash
root. It checks every derived cell reference, recipient, amount and delivered transaction
against the immutable journal. Every signed authorization must be expired, its transaction
unadmitted, its session unconsumed, and the treasury nonce must not have advanced past it.
Previously confirmed or partly executed grants are refused and require separate reconciliation.
Successful recovery changes only the receipt to rejected; it preserves delivered identities,
signed envelopes and quota/audit records. Run this offline: the tool does not coordinate with
a concurrently running RPC writer. Do not restore an older faucet snapshot over later grants.

Restart RPC and rounds, restore admissions when ready, and verify advancing healthy pinned
RPC status with `python3 scripts/probe-kanalen-rpc.py --require-healthy`. Then run
`scripts/test-ios-wallet-e2e.sh` from a clean checkout to create and fund a fresh simulator
wallet, verify at least two proof-bearing cells, and check persistence after relaunch.
Keep the retained simulator and private XCTest output; do not publish recovery words or keys.

Release activation installs complete service plists in `~/Library/LaunchAgents` before
bootstrapping them, so the validator and RPC configuration survives the next login.
