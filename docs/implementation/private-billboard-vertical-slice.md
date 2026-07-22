# Private billboard native-token vertical slice

Tracked by [GitHub issue #27](https://github.com/advatar/ActiveChain/issues/27).

## Delivered boundary

The `activechain-private-billboard` crate implements a bounded reference lifecycle:

1. A public native Coin Cell is atomically shielded into a committed billboard permit.
2. The permit is ML-KEM encrypted to a wallet and rediscovered after restart from the same seed.
3. A canonical senderless post action is encrypted for the protected-ordering boundary.
4. The reference verifier checks the private permit opening, nullifier, cooldown/save-up rule,
   screening window, penalty, successor state, policy revision, fee, and public post.
5. Native cash and billboard state advance clone-then-commit: the same nullifier pays the shielded
   post fee, the successor commitment becomes current, and both escrow balances remain equal.
6. After required moderation decisions exist, a terminal proof consumes the successor and creates
   one public native withdrawal. Replay and partial failure leave both states unchanged.

Public `PostPublicInputs` contain chain/asset identifiers, state anchor, nullifier, successor
commitment, random post identifier, content, height, fee amount, dummy bit, and policy revision.
They contain no principal or public fee ticket. The cash fee intent names only the configured fee
recipient, not the permit owner.

## Security status

This is an executable semantic and integration vertical slice, not a production zero-knowledge
system. `BillboardVerifier` directly receives the private witness and issues a receipt whose fields
cannot be constructed outside the crate. Validators must not use that reference verifier across a
privacy boundary because it sees the permit opening. Production anonymity still requires replacing
it with a sound zero-knowledge prover/verifier for the identical public statement.

The implementation demonstrates senderless wire values, pre-order encryption, authenticated note
delivery, atomic native accounting, replay resistance, restart recovery, and the full application
state machine. It does not claim IP/timing unlinkability, multi-device wallet synchronization,
production note-tree witnesses, audited circuit soundness, or Ethereum bridge parity.

## Validation

- `cargo fmt --all -- --check`
- `cargo clippy -p activechain-private-billboard --all-targets -- -D warnings`
- `cargo test -p activechain-private-billboard -p activechain-privacy-kernel -p activechain-cash-kernel`
- `cargo test --workspace --all-targets`
