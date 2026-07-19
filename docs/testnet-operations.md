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

## Run the process rehearsal

```sh
bash scripts/rehearse-validator-processes.sh
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

Metrics exposed by `ValidatorService::metrics()` are intentionally monotonic:
`proposals`, `votes`, `finalized_certificates`, and `rejected_messages`.
