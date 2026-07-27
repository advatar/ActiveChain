# Validity-proof liveness and admission (v1)

This policy makes prover outages observable without allowing them to silently weaken consensus.

## v1.0 development profile

- Validator re-execution is authoritative for block validity.
- A proof may be attached as independently verifiable evidence, but its absence does not make a
  valid re-executed block invalid.
- A malformed proof is rejected and recorded; it is never ignored or substituted.
- A block whose re-execution fails is rejected regardless of proof presence.

## Mandatory-proof profile

Profiles that activate proof-carrying validity require a valid proof for every applicable block.
The admission state is one of:

- `proof_verified`: proof and re-execution both pass;
- `proof_missing`: block is not admissible and remains pending;
- `proof_invalid`: block is rejected and evidence is retained for audit;
- `reexecution_failed`: block is rejected even if a proof verifies.

There is no automatic fallback from `proof_missing` to stake authority. A profile upgrade must
name the activation height, proof kind, verifier revision, and rollback/halting behavior in its
governed authorization. Unknown proof kinds fail closed.

## Qualification requirements

Implementations must test prover outage, delayed proof arrival, malformed proof substitution,
verifier-version mismatch, and restart equivalence. The vectors must distinguish pending from
rejected states and must never advance finalized height on a non-admissible block.
