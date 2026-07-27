# Faucet finalized funding v1

The public faucet is a testnet funding service, not a balance oracle. It may create a request and
challenge decision, but a wallet credits funds only after a finalized Coin Cell transition and
proof-bearing receipt are verified against the testnet genesis commitment.

The ingress path is: authenticated request → operator challenge decision → one-shot faucet grant
→ signed transaction intent → validator admission → finalized block → owner/asset Coin Cell proof
→ receipt resolution. Every stage binds the same recipient, test asset, amount, nonce, and genesis.

Retries are idempotent by request reference. A restart may replay a pending request but can never
issue a second grant. Forged chain IDs, altered amounts, optimistic receipts, stale finality, and
recipient substitutions are rejected. Operator budgets and cooldowns are monotonic and durable.
