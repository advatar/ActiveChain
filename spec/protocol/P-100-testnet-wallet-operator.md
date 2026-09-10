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

## Key-derived wallet enrollment

A wallet principal derived by `wallet_principal_id` MAY first register its ML-DSA-44 cash key
using `CashKeyEnrollmentV1` (0x01D3, schema 1). The signed transcript binds the complete public
key, chain ID, inclusive start height and expiry. Its validity window MUST be at most 120 blocks.
The principal MUST own a finalized Coin Cell; enrollment proves key ownership, not a human
identity or an issuer credential. Composite identity credentials are optional application policy.

The candidate transition MUST reject an existing authorization lane, including one controlled by
the same key. Enrollment MUST NOT replace keys, reset nonces, or authorize rotation or recovery.
It stages a new lane at nonce zero and commits the exact enrollment action identifier in the
ordered `ACTIVECHAIN-BLOCK-CASH-ACTIONS-V1` root. The complete ingress successor MUST remain
unpublished until consensus finalizes that root. Commit MUST compare the full ingress predecessor,
including authorization state, because enrollment does not change the Coin Cell root.

A payment from a newly enrolled lane MUST have a height strictly greater than its enrollment
height. RPC admission uses only finalized ingress, so it cannot authorize spending from a pending
registration. Enrollment and payment submissions share bounded durable admission and retention;
enrollment does not charge a transfer fee. It is limited to funded principals and the existing
256-lane testnet capacity. Expanding that capacity or supporting rotation is separate protocol work.

RPC request envelope revision 4 adds `EnrollCashKey` (15) and `CashSubmissionEvidence` (16).
RPC response revision 5 adds evidence variant 13; advertised RPC schema revision is 5. Evidence
contains at most 32 ordered action identifiers and a bounded native finality bundle. Clients MUST
verify pinned chain/genesis, the exact action identifier and ordered cash-action root. A server's
pending or finalized status label alone MUST NOT establish enrollment or payment. Merchant
checkout additionally verifies the exact recipient output, amount, and customer change.
