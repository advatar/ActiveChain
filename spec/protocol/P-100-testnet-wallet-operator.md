# P-100: Testnet wallet and operator contract

- Status: Draft 0.1
- Protocol version: Development

This document defines the minimum wallet/operator boundary for the first public testnet. Wallets
construct canonical intents locally; nodes validate and admit canonical transfers. No node endpoint
accepts a private key or an unsigned “send amount” shortcut.

## Identity derivation

The testnet POC command is:

```text
activechain-wallet derive <index> <epoch> <activation-height>
```

It deterministically derives an ML-DSA testnet principal commitment and public key. The command
MUST print public material only. Seed material is kept out-of-band until the encrypted keystore
format is finalized.

## Transfer boundary

The wallet performs Coin Cell discovery, deterministic input selection, fee estimation, policy
evaluation, and canonical `CoinTransfer` construction. It MUST select a distinct fee reserve and
bind a validity height. The node receives only the canonical transfer envelope and its PQ witness.

## Operator safety

Operators MUST verify the chain ID, protocol version, genesis hash, validator-set root, and wallet
principal before submitting funds. Testnet tooling MUST reject mismatched genesis material and must
never reuse production or development seeds across networks.

## Launch acceptance

The release rehearsal MUST demonstrate wallet derivation, funded Coin Cell discovery, a signed
transfer, fee charging, replay rejection, restart recovery, and convergence across three
authenticated PQ validator processes.
