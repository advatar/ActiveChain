# MCP proposal gateway v1

`activechain_propose_transfer` admits an exact action for later native-wallet review. A successful
tool result means only that the proposal was durably recorded. It never means approved, signed,
submitted, settled, or finalized.

## Authority and intent binding

The host receives an `AuthenticatedProposalContext` from the native agent/capability boundary. The
gateway then independently requires exact matches for chain, wallet, agent principal, capability,
asset, optional recipient restriction, expiry, single-action ceiling, cumulative remaining budget,
and maximum fee. The request nonce and replay domain are included in the canonical action intent.

The client supplies the expected intent commitment. The gateway reconstructs `ActionIntentV1`,
canonically encodes it, derives its domain-separated 384-bit commitment, and rejects any mismatch.
Changing the amount, fee, recipient, resource, nonce, expiry, principal, capability, chain, wallet,
or request ID therefore changes the commitment.

## Lifecycle and replay

Before returning, the gateway atomically persists a tagged canonical `ProposalJournalV1` snapshot
and syncs both file and parent directory. Exact retries return the same proposal ID with
`duplicate: true`. A conflicting request-ID reuse, or reuse of an agent nonce/replay-domain pair
under another request ID, fails closed. Cumulative admitted amounts are bounded per capability and
remain consumed after restart.

The structured audit event contains only proposal ID, action class, approval class, and duplicate
status. It contains no credentials, signatures, secrets, or reusable authorization material.

## Deliberate exclusions

This crate contains no signing key, signer interface, transaction builder, submitter, arbitrary RPC
forwarder, or generic signing tool. Its only consequential output is a proposal requiring
`native_wallet_review` (or review with a deterministic warning). Native-wallet approval and dispatch
belong to #358. Anchor proposals remain disabled until their policy-specific canonical DTO exists.
