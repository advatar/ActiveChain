# Independent-client conformance budget v1

Independent verification is a launch gate, not a promise that a second client reuses Rust code.
The first conformance surface is deliberately bounded to the v1.0 launch contract:

- canonical codec and envelope framing;
- principals, capabilities, policy decisions, object state, and cash transitions;
- validator-set and ML-DSA context binding;
- proof/header reservation and strict unknown-feature rejection;
- finalized receipt and state-proof verification.

The second client must implement these from the normative specifications and published vectors,
with no dependency on ActiveChain Rust crates. It must pass all positive and malformed vectors,
including canonical ordering, bounds, domain separation, replay, and unsupported-version cases.

The milestone is staged: codec/primitives first, cash and authorization second, finality and
proof reservations third. Later shielded, compute, and advanced proof profiles add new conformance
profiles rather than changing v1.0 semantics. A profile cannot be called independently verified
until two implementations pass the same frozen vector set.
