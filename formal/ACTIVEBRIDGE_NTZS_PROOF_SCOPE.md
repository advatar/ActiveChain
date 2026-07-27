# ActiveBridge nTZS adapter proof scope

`formal/lean/ActiveChain/Payments.lean` contains the abstract nTZS API and webhook mappings refined
by `connectors/ntzs/src/lib.rs`.

Mechanically checked properties:

- every reviewed API state maps to `pending`, `succeeded`, `rejected`, or fail-closed `unknown`;
- an unrecognized API state maps to `unknown`;
- the provider's `withdrawal` `burned` state is not success;
- an unsupported webhook is not admitted;
- accepted nTZS webhook evidence is connector-authenticated, not ActiveChain-finalized.
- provider precision above the registered asset scale is rejected;
- an accepted decimal amount equals the exact expected atomic-unit quantity;
- an accepted provider response binding has exactly the expected unit, asset, reference, and
  atomic quantity.
- only a prepared provider attempt is dispatch-ready;
- an attempt that may have reached the provider requires reconciliation and cannot dispatch again;
- the dispatch boundary can be crossed only once;
- exact request replay is idempotent while changed request commitments are rejected;
- a changed provider reference cannot replace the first bound reference.
- a typed transfer destination emits exactly one of `toUserId` or `toAddress`;
- an accepted typed core request satisfies its operation minimum.

The Rust tests additionally execute the fixed endpoint/key policy, exact documented status and
error mappings, webhook HMAC binding, body substitution, timestamp substitution, stale/future
delivery, unsupported/malformed events, exact evidence class, durable replay across restart,
duplicate rejection, snapshot corruption rejection, and transport/body/idempotency bounds.
Failed replay persistence is also checked not to mutate the in-memory replay barrier.
The response-schema tests preserve large decimals beyond IEEE-754 precision, execute the
published amount vectors, reject fractional TZS/exponents/unsupported assets, and require exact
reference, asset, unit, and quantity binding before emitting an observation.
The attempt-journal tests cover exact/changed request replay, durable pre-dispatch state, restart
equivalence, ambiguous timeout decisions, immutable provider references, corruption, canonical
ordering, unknown attempts, and failed-persistence non-mutation.
The typed-request tests execute the published request vectors and enforce exact decimal
serialization, deposit/withdrawal minimums, bounded safe-subset identifiers, canonical Tanzanian
phone form, HTTPS card callbacks, EVM address shape, and destination exclusivity.

The model assumes correspondence between each Rust string match and its Lean constructor. It does
not prove HMAC-SHA256 security, SHAKE256 collision resistance, provider honesty, secret custody,
clock correctness, TLS/DNS/proxy security, JSON parser correctness, filesystem or operating-system
semantics, cross-process locking, arbitrary JSON-to-Lean refinement, provider settlement,
external-chain finality, native Coin Cell authorization/conservation, compiler correspondence, or
production qualification. Those remain explicit external assumptions and later refinement
obligations.

Counterexamples must be retained, minimized, and used to fix the model or implementation rather
than weakening a claimed property.
