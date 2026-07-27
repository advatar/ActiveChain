# Testnet faucet ingress v1

The faucet is a testnet-only transaction producer. It never credits a wallet from local UI state.

## Flow

1. The wallet submits a canonical faucet request bound to chain ID, genesis commitment, recipient,
   challenge solution, policy revision, and idempotency key.
2. The faucet admits at most one request for the key and records a durable pending receipt before
   submitting the authorized Coin Cell transition to validator ingress.
3. The validator returns a transaction/action reference. The faucet reports `pending` until a
   finalized certificate proves the exact block, transaction, recipient, amount, and cash root.
4. Only `finalized` status may update wallet state. `rejected`, `expired`, and `invalid` statuses
   never credit balances and remain queryable for audit.

## Safety requirements

- Requests are rejected when chain/genesis or protocol revision differs.
- Global budget, recipient cooldown, lifetime cap, and challenge policy are checked atomically.
- Restart restores the request journal and cannot issue a second grant.
- Finalization verifies the exact finality bundle and Coin Cell membership proof.
- iOS/macOS clients display pending/unavailable state and never synthesize a balance.
