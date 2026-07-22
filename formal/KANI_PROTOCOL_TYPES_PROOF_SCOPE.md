# Kani protocol-types proof scope

Kani 0.67 checks five harnesses over production `protocol-types` code. An
arbitrary numeric consensus context and quorum certificate round-trip through
the strict canonical envelope; every truncation, a trailing byte, and every
single-bit type/version header substitution of a fixed production QC are
rejected; and the shared strict-two-thirds helper exactly matches independent
checked multiplication and comparison for all `u128` inputs.

This is a bounded compositional result. Digest bytes are fixed while numeric
fields are symbolic; signature verification, SHAKE256 internals, allocation
failure, arbitrary schemas, and distributed consensus behavior are outside the
claim. A 64-step unwind bound covers the fixed 48-byte digest comparisons. The
crate pins an honest Rust 1.93 MSRV because Kani 0.67 embeds Rust 1.93; the
workspace may use a newer compiler.

The companion commitment harness proves that the production preimage builder
places the fixed prefix, transcript version, domain, type, schema, exact body
length, and every byte of a body through four bytes in distinct fixed fields.
SHAKE256 itself remains an explicit cryptographic assumption.
