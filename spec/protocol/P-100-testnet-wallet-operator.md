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
bind a validity height. It then constructs `CashAuthorizationRequestV1`, binding the chain ID,
sender, next nonce, one-shot session ID, session expiry, recipient commitment, and exact transfer,
and signs its domain-separated canonical transcript with ML-DSA-44. The node receives only the
outer `AuthorizedCashTransferV1` envelope; bare transfers and the legacy unkeyed session witness
are not network-admissible.

The node MUST resolve the sender's authorization key from finalized chain state, not from the
request. It MUST atomically consume the nonce, session, payment inputs, fee input, and ledger
transition. The current in-memory implementation satisfies the admission predicate but does not
yet provide finalized key provenance or crash-atomic persistence of that joint state; both remain
release gates.

## Operator safety

Operators MUST verify the chain ID, protocol version, genesis hash, validator-set root, and wallet
principal before submitting funds. Testnet tooling MUST reject mismatched genesis material and must
never reuse production or development seeds across networks.

## Launch acceptance

The release rehearsal MUST demonstrate wallet derivation, finalized authorization-key discovery,
funded Coin Cell discovery, a signed transfer, fee charging, nonce/session/input replay rejection,
crash recovery of the joint ledger and authorization state, and convergence across three
authenticated PQ validator processes.
