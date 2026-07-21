# ActiveChain PQ testnet operations

This runbook describes the deterministic local rehearsal used before opening a
public testnet slot. Every validator must use the same genesis manifest and a
distinct validator index.

## Generate a manifest

```sh
cargo run --release -p activechain-consensus-runtime --bin genesis-tool -- \
  ./testnet/genesis.bin 1 1 3
```

The manifest binds epoch, activation height, stake, validator IDs, and ML-DSA-44
public keys. Keep it immutable after distribution.

## Derive an operator wallet

```sh
cargo run --release -p activechain-wallet-core --bin activechain-wallet -- \
  derive 0 1 0
```

Register the printed principal in the testnet faucet manifest. Never reuse a seed or principal
between testnet genesis files.

## Fund and submit a transfer

The faucet issues a test-only Coin Cell on the exact genesis chain. The wallet must discover a
funded cell, reserve a distinct fee cell, construct a canonical `CoinTransfer`, and submit it to
transaction ingress. Ingress applies the cash-kernel transition and rejects a repeated transition
ID.

## Run the process rehearsal

```sh
bash scripts/rehearse-validator-processes.sh

## Build and deploy the Kanalen bundle

The manually triggered `Kanalen testnet deployment` workflow builds pinned release binaries and
publishes a checksum. During the home-network phase, set its deploy host to `192.168.2.126` and
enable deployment. The workflow requires `KANALEN_DEPLOY_USER` and `KANALEN_DEPLOY_KEY` secrets,
copies the bundle to `/Volumes/ActiveChain/testnet/`, and never exposes validator peer ports.
```

The rehearsal must produce one persisted snapshot per validator and report
`proposals=1 votes=1 rejected=0` for every process. A rejected-message count
greater than zero is a release blocker.

## Operator gates

- Do not admit a validator whose genesis public key does not match its derived
  signer.
- Do not accept consensus frames before the ML-DSA peer handshake succeeds.
- Stop rollout if any validator reports rejected messages, divergent genesis
  roots, or a snapshot that cannot be loaded after restart.
- A testnet announcement requires a green self-hosted CI run and successful
  partition, replay, late-vote, restart, and sustained-load rehearsals.
- Public faucet and transaction-ingress endpoints may only be announced with the signed genesis
  manifest; placeholder endpoints are not launch infrastructure.

Metrics exposed by `ValidatorService::metrics()` are intentionally monotonic:
`proposals`, `votes`, `finalized_certificates`, and `rejected_messages`.
