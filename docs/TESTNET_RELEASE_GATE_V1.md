# Testnet release gate v1

The testnet is releasable only when every mandatory gate below has evidence attached to the
release commit. This is a development gate, not a production-audit claim.

- [ ] Validator round runner reaches finalized height with the configured genesis.
- [ ] Execution exports finalized Coin Cell records and authenticated membership proofs.
- [ ] Cash snapshots persist with finalized header, cash root, and restart verification.
- [ ] RPC ingest publishes owner-scoped records only after finality/root verification.
- [ ] Faucet submits real authorized transitions and exposes pending/finalized/rejected receipts.
- [ ] Faucet replay, concurrency, forged-chain, exhaustion, restart, and privacy vectors pass.
- [ ] iOS/macOS wallets load real testnet status and only credit finalized proofs.
- [ ] Public RPC identity, health/staleness, proof support, and chain genesis are verified.
- [ ] Independent client passes the v1 conformance vectors.
- [ ] No release notes use “audited”, “AML compliant”, or “production finality” without evidence.

Any unchecked gate blocks release. A reset of the development genesis requires rerunning every
identity, faucet, wallet, and RPC gate; old receipts and snapshots must not be reused.
