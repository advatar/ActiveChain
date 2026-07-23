# Verifier SDK boundary

The verifier SDK is a bounded, read-only trust boundary for downstream applications. It accepts
canonical public protocol values only, retains no caller-owned buffers, and exposes the same stable
numeric result codes through Rust and C.

Revision 1 publishes independent ABI, schema, and protocol revision queries. Callers must check all
three before verifying values. The ABI and SDK schema revisions describe the exported function and
result-code contract; the protocol revision identifies the ActiveChain consensus rules understood
by this build.

The first semantic entry point, `activechain_verify_principal_code`, does more than inspect envelope
framing. It requires the registered Principal type and schema, exact bounded framing, a complete
canonical body, and all Principal cross-field invariants. In particular, malformed enum values and
an update height preceding the creation height are rejected. Rust callers use `verify_principal`
or `verify_principal_code` and receive the same stable result category as C callers.

Capability verification follows the same boundary. `activechain_verify_capability_code` validates
the complete canonical grant and its cross-field invariants.
`activechain_verify_capability_attenuation_code` additionally decodes a bounded parent-child pair
and mechanically proves every authority dimension is attenuated. A well-formed child that broadens
actions, scope, limits, validity, delegation, constraints, or revocation state returns the stable
relation-mismatch result rather than being mistaken for a decoding failure.

The remaining issue #88 entry points will follow this pattern for APL decisions, state witnesses,
finalized blocks, receipts, and joined authorization chains. No function accepts secret material.
