# dBrowser verifier SDK boundary v1

The downstream SDK is a versioned, proof-bearing boundary—not a framing or commitment helper.
Each verifier accepts canonical bytes plus trusted network parameters and returns structured
`verified`, `invalid`, `unsupported`, or `unavailable` results.

The v1 surface covers principal and capability semantics, authorization chains, policy decisions,
state membership/non-membership proofs, finalized headers and quorum certificates, block receipts,
and asset/owner/action evidence. Every result exposes the verified chain identity, protocol and
verifier revisions, finalized height, and exact commitment it checked.

Malformed lengths, trailing bytes, wrong chain/genesis, stale finality, substituted keys,
unsupported revisions, and proof/profile mismatches fail closed. The SDK never fetches mutable
remote policy or silently trusts an RPC response; callers provide trusted network parameters and
may run verification fully offline.
