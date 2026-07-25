# P-122 — Multi-asset Coin Cell binding

Status: implementation slice (draft for testnet qualification)

Every fungible Coin Cell, transition, authorization, proof, and receipt is bound to one
canonical `AssetId`. The native currency is an ordinary registered asset; it is not a
special untyped path.

## Canonical rules

1. A cell amount is interpreted only with the asset definition committed by its `AssetId`.
2. Inputs and outputs in one transfer must use the same `AssetId`; cross-asset exchange is
   represented by two independently authorized legs and never by implicit conversion.
3. Asset definitions are strictly ordered by `AssetId` in the finalized registry. Duplicate,
   missing, expired, or superseded definitions are invalid at admission.
4. Supply conservation is checked per asset: inputs plus authorized mint equals outputs plus
   authorized burn. Overflow and decimal rescaling are rejected, never rounded.
5. Every receipt and state proof includes the asset identifier and the registry commitment;
   a proof without both bindings is malformed.
6. Wallet selection, fee calculation, and policy evaluation must preserve the asset identifier
   through signing and submission. A UI label or symbol is never an authority.

## Privacy and regulated profiles

Asset identity and public supply metadata may be disclosed, while holder identity, KYC/KYB
material, sanctions evidence, and reserve payloads remain off-chain. A regulated asset may
require a selected jurisdiction profile, but profile selection cannot silently change an
asset's identifier or supply rules.

The next implementation slices are: owner-and-asset proof-bearing RPC pagination, wallet ABI
asset selection, then consensus admission and formal conservation proofs.
