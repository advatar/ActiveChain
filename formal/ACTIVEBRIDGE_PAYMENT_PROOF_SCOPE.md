# ActiveBridge payment lifecycle proof scope

`formal/lean/ActiveChain/Payments.lean` models the provider-independent lifecycle represented by
`activechain-payment-types`.

Mechanically checked properties:

- terminal payment states have no permitted successor;
- every successor advances sequence by exactly one;
- a well-formed external confirmation cannot claim ActiveChain-finalized evidence;
- a well-formed finalized state carries the declared finality fields.
- a provider-observation successor preserves its attempt and advances sequence exactly once.
- exact observation replay does not mutate journal state, and a rejected successor produces no
  replacement state in the abstract journal model.
- provider terminal states have no successor, and deterministic simulator cursors never regress.

The Rust crate additionally checks intent identity across successors, exact asset identity,
minimum-output ordering, checked fee arithmetic, idempotency-body binding, canonical round trips,
malformed enum tags, and trailing-data rejection.

The model assumes that identifiers, commitments, transaction references, and block references are
nonzero and authentic where required. It does not prove provider honesty, signature security,
asset-policy acceptance, durable persistence, Coin Cell conservation, inclusion/finality proof
verification, compiler correspondence, or arbitrary serialized-input refinement. Those are
required later refinements, not properties implied by this model.

Counterexamples must be retained, minimized, and used to fix the model or implementation rather
than weakening a claimed property.
