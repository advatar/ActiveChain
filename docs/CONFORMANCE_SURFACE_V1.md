# ActiveChain v1 conformance surface

This document is the implementation-independent boundary for a second client. A conforming
client does not link Rust crates; it consumes canonical envelopes and the deterministic vectors
published under `testing/vectors/`.

## Required codecs

- Canonical envelope framing: type tag, schema version, bounded body, and no trailing bytes.
- Lowercase hexadecimal digest representation for CLI fixtures.
- Strict enum decoding: unknown tags and values are rejected, never ignored.

## Required v1 surfaces

1. Network identity: chain ID, genesis commitment, protocol revision, finalized height, health,
   and supported proof kinds from `RpcStatus`.
2. Finality: verification of the signed finality bundle against the configured genesis.
3. Native cash: Coin Cell membership proofs, owner binding, cash-root binding, and exact height.
4. Fungible assets: AssetId, policy commitment, issuer registration, issuer approval, supply
   transition, and supply-attestation bindings.
5. Credentials: issuer/schema allowlists, validity windows, status-registry freshness, and holder
   predicate bindings.

## Qualification gates

- Positive and malformed vectors must produce the same accept/reject result as the reference
  implementation.
- Every accepted record must round-trip to byte-identical canonical encoding.
- Unknown type tags, schema versions, trailing bytes, zero commitments, inverted windows, and
  cross-chain substitutions must fail closed.
- A second implementation must pass the vectors without depending on Rust implementation details.

The NFT query tag is reserved in v1, but proof verification remains unsupported until the
finalized cash-root schema includes an authenticated NFT tree; clients must report that state
explicitly rather than treating it as a valid proof.
