# ActiveChain first-testnet release checklist

This checklist is the release gate for the first public testnet. A green unit-test suite alone is
not sufficient.

## Required services

- Three or more authenticated PQ validator processes with canonical genesis.
- Snapshot/restart recovery and partition reconnect rehearsal.
- A transaction-ingress service that accepts only canonical `CoinTransfer` envelopes and PQ
  authorization witnesses. It MUST never accept private keys.
- Wallet CLI support for deterministic testnet identity derivation, Coin Cell selection, fee
  reserves, and transfer construction.
- Faucet/genesis funding tool bound to the testnet genesis hash.

## dBrowser compatibility gate

Before publishing a verifier package, run:

```sh
bash scripts/check-verifier-manifest.sh
cargo test -p activechain-verifier-api
```

The manifest checker verifies every published vector hash and every malformed fixture. A production
package additionally requires compiled C bindings and finality/state/DA proof fixtures.

## Wallet acceptance

1. Derive two independent ML-DSA testnet identities.
2. Fund one identity from the testnet faucet.
3. Discover Coin Cells and construct a transfer with a distinct fee reserve.
4. Submit the canonical envelope through transaction ingress.
5. Observe finality on all validators and index the recipient balance.
6. Replay the envelope and confirm deterministic rejection.
7. Restart one validator and confirm the transfer remains finalized.

## Economics acceptance

- Fee quote and base-fee update are deterministic.
- Fee revenue enters the security budget and burns follow the supply equation.
- Verifier bonds, duty receipts, challenge resolution, slashing splits, and reward redemption use
  explicit Coin Cell transfers.
- No reward receipt, shielding operation, refund, or redemption creates native value twice.

## Release blockers

The testnet MUST NOT be announced until transaction ingress, faucet funding, and the seven-step
wallet acceptance rehearsal are implemented and passing on the local ARM64 runner.
