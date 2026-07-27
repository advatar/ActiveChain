# Regulated screening profile v1

Screening providers keep source lists, raw matches, analyst notes, and identity documents off
chain. ActiveChain receives a signed commitment-only decision bound to the exact chain action.

## Profile fields

- authoritative list identifiers and version commitments;
- refresh deadline and provider-signing key commitment;
- canonical matching parameter commitment (normalization, threshold, aliases, address analytics);
- outcomes `cleared`, `match`, `inconclusive`, and `manual_review`;
- freeze/release decision commitment, reason commitment, reviewer set, quorum, and expiry.

Expired lists, unknown provider keys, stale decisions, and mismatched parameters fail closed.
Overrides require the configured reviewer quorum and cannot turn a `cleared` record into an
unbounded exception. Every decision and override is replay-bound to profile, chain, action, and
nonce; private evidence remains provider-held and auditable under the retention policy.

Jurisdiction profiles are selected before admission. Ambiguous selection returns `manual_review`
and cannot silently fall back to a weaker profile.
