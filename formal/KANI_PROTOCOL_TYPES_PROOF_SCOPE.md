# Kani protocol-types proof scope

Kani 0.67 checks seven harnesses over production `protocol-types` code. Three
admission harnesses prove exact overflow-safe frame layout and monotonic replay
admission. Three native-asset harnesses prove capped minting, non-underflowing
burns, and exact supply-attestation binding to policy identity, issuer,
commitment, and issued supply. A fourth native-asset harness proves corporate-action admission
requires the exact asset, policy commitment, authority set, and half-open finalized-height window.

This is a bounded compositional result. Digest bytes are fixed while numeric
fields are symbolic; signature verification, SHAKE256 internals, allocation
failure, arbitrary schemas, and distributed consensus behavior are outside the
claim. Production `FungibleSupplyAttestationV1::binds_policy` computes the real
policy commitment and then calls the exact private field-binding helper proved
by Kani. Corporate-action identity hashing and registry persistence remain outside the symbolic
claim; ordinary tests exercise those composed paths. The companion
commitment harness covers production transcript construction. A 64-step unwind
bound covers every loop reachable from the six structural harnesses and
unwinding assertions remain enabled. The crate pins an honest Rust 1.93 MSRV
because Kani 0.67 embeds Rust 1.93; the workspace may use a newer compiler.

The companion commitment harness proves that the production preimage builder
places the fixed prefix, transcript version, domain, type, schema, exact body
length, and every byte of a body through four bytes in distinct fixed fields.
SHAKE256 itself remains an explicit cryptographic assumption.

The live consensus socket and protected-state persistence paths call the three
admission helpers. Protected snapshots additionally use an atomic, versioned,
exact-length wrapper with a domain-separated SHAKE256 checksum; runtime tests
cover restart, truncation, payload corruption, trailing bytes, and failed
atomic replacement. Kani does not model the filesystem, crash durability of
the OS, or SHAKE256 internals.
