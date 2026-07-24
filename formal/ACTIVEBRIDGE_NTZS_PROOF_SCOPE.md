# ActiveBridge nTZS adapter proof scope

`formal/lean/ActiveChain/Payments.lean` contains the abstract nTZS API and webhook mappings refined
by `connectors/ntzs/src/lib.rs`.

Mechanically checked properties:

- every reviewed API state maps to `pending`, `succeeded`, `rejected`, or fail-closed `unknown`;
- an unrecognized API state maps to `unknown`;
- the provider's `withdrawal` `burned` state is not success;
- an unsupported webhook is not admitted;
- accepted nTZS webhook evidence is connector-authenticated, not ActiveChain-finalized.

The Rust tests additionally execute the fixed endpoint/key policy, exact documented status and
error mappings, webhook HMAC binding, body substitution, timestamp substitution, stale/future
delivery, unsupported/malformed events, exact evidence class, durable replay across restart,
duplicate rejection, snapshot corruption rejection, and transport/body/idempotency bounds.
Failed replay persistence is also checked not to mutate the in-memory replay barrier.

The model assumes correspondence between each Rust string match and its Lean constructor. It does
not prove HMAC-SHA256 security, SHAKE256 collision resistance, provider honesty, secret custody,
clock correctness, TLS/DNS/proxy security, JSON parser correctness, filesystem or operating-system
semantics, cross-process locking, amount/asset correspondence, provider settlement, external-chain
finality, native Coin Cell authorization/conservation, compiler correspondence, or production
qualification. Those remain explicit external assumptions and later refinement obligations.

Counterexamples must be retained, minimized, and used to fix the model or implementation rather
than weakening a claimed property.
