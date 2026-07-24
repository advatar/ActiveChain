# Agent-enrollment lifecycle proof scope

`formal/lean/ActiveChain/AgentEnrollment.lean` models the monotonic lifecycle accepted for one
chain-, wallet-, agent-, and request-bound enrollment evidence stream.

Mechanically checked properties:

- finalized evidence preserves the exact transaction from submitted evidence;
- submitted evidence may move to one finalized, rejected, or expired terminal outcome;
- terminal outcomes are immutable except for exact idempotent replay;
- finalized evidence cannot regress to expired evidence.

The model assumes that common chain, wallet, agent, and request commitments have already matched.
It also assumes cryptographic signature authenticity, collision resistance, trustworthy finalized
block and inclusion commitments, and correct observation heights. The Rust constructors and tests
enforce those concrete bindings, but compiler correspondence and arbitrary serialized-input
refinement are not proved by this Lean model. Counterexamples must be retained, minimized, and used
to fix the model or implementation rather than weakening a claimed property.
