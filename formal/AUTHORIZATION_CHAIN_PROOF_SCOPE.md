# ActiveChain authorization-chain proof scope

`formal/tamarin/activechain_authorization_chain.spthy` is a finite symbolic composition of the
launch-critical authorization path described by P-021, P-022, P-023, P-030, and P-031. It connects
an ML-DSA-authenticated action request to a verified credential fact, a two-hop attenuated
capability fact, a finalized object-state membership fact, an exact APL Permit, and one atomic
object-version transition. It is not a claim that the complete Rust authorization stack or the
underlying cryptographic primitives have been formally verified.

## Modeled protocol slice

One fresh chain/epoch context registers independent ML-DSA-65 verification keys for an actor, a
credential issuer, a root capability issuer, and two delegates. The finite trace then performs:

1. issuance of one subject-bound credential and its signed-credential identifier;
2. issuance of one root capability to delegate one;
3. delegation to delegate two with structural attenuation of every modeled authority dimension;
4. delegation to the actor with a second structural attenuation;
5. commitment of one object identifier, version, control-policy commitment, action, and exact
   membership-proof term under one finalized state root;
6. creation of two concurrent, replayable action requests that bind the chain, epoch, height,
   actor, action, object, version, policy, credential identifier, leaf capability, operation, and
   nonce under ML-DSA-65;
7. acquisition of one linear authorization snapshot by at most one request;
8. exact credential, capability-chain, and state-proof verification events;
9. an APL Permit requiring the exact verified schema and leaf capability, no matching forbid, and
   a single-use-consumption obligation; and
10. one transition from `version` to the symbolic checked successor `next_version(version)`.

Credential and capability bytes are public and may be replayed. The action-request bytes pass
through Tamarin's Dolev-Yao network. The only accepting request rule matches the complete signed
transcript and consumes its pending request. The authorization snapshot, leaf use, and object
write are linear facts shared by both competing requests.

## Proved all-traces properties

The gate checks thirteen universal lemmas:

- every accepted transition has the complete, strictly ordered actor-authentication, credential,
  capability-chain, state-proof, and APL events with identical chain, epoch, height, actor, action,
  object, version, policy, credential, capability, schema, and state root;
- accepted action authentication has a prior exact ML-DSA-65 signed-request origin;
- every verified credential fact has the exact prior ML-DSA-65 issuance origin, subject, schema,
  status registry, signed statement, and credential identifier;
- every verified capability chain has exact root, level-one, and level-two ML-DSA-65 issuance
  provenance with the required issuer/holder/parent links;
- the two delegation steps construct nested `subset_*`, `lower_limit`, `later_start`,
  `earlier_end`, and `lower_depth` authority terms and preserve the single-use and constraint
  dimensions;
- every accepted state proof has a prior finalized object commitment with identical proof, root,
  object, version, policy, and action;
- every accepted signature suite in this slice is ML-DSA-65;
- a request context cannot be substituted while retaining an operation accepted by a transition;
- finalized credential revocation blocks any later transition using that credential;
- finalized root, intermediate, or leaf capability revocation blocks any later transition using
  that two-hop chain;
- one leaf single-use right can be reserved for only one operation even though two signed requests
  compete;
- one operation cannot finalize twice; and
- one object/version write cannot finalize twice, including through distinct competing operations.

The final two uniqueness statements are useful consequences of the same linear authorization
snapshot and transition token, but remain separately gated because they expose operation replay and
object-write concurrency failures at different protocol boundaries.

## Non-vacuity witnesses

Five `exists-trace` lemmas require an executable complete transition, two competing requests with
one winner, credential revocation, ancestor capability revocation after delegation, and leaf
revocation after the full two-hop chain. These witnesses prevent the universal claims from passing
only because issuance, delegation, authorization, or revocation is unreachable.

## Symbolic assumptions and explicit limits

- Tamarin's perfect signing primitive represents ML-DSA-65. This is a symbolic unforgeability and
  transcript-binding model, not a computational reduction for FIPS 204 or verification of the Rust
  ML-DSA provider.
- The model does not reveal or compromise signing keys and therefore makes no post-compromise,
  rotation, recovery, side-channel, or implementation-fault claim.
- P-021 credentials and P-022 grants do not themselves contain a chain identifier. This model binds
  their exact identifiers into a chain/epoch-specific signed action request and uses keys registered
  in that context. Reuse of the same issuer key and artifact across independently configured chains
  remains a protocol-policy question outside this finite context.
- State membership is an exact proof term paired with an honestly committed finalized-object fact.
  SHAKE256 collision resistance, the P-031 96-level proof fold, canonical decoding, checkpoint
  finality, validator-set changes, and state sync are separate proof and implementation obligations.
- `subset_actions`, `subset_scope`, `lower_limit`, `later_start`, `earlier_end`, and `lower_depth`
  are free symbolic constructors. The theorem proves that no unattenuated value can enter either
  child record; numeric inequalities and selector containment still require the Rust/Lean
  refinement boundary.
- APL is the exact composition boundary, not the full P-023 evaluator. The model fixes one matching
  permit, an absent forbid, and one single-use obligation. Predicate evaluation, metering,
  obligation batching, and arbitrary policy sets remain covered by their executable and Lean
  models.
- Revocation and current budget status are acquired atomically in one finalized authorization
  snapshot. A revocation finalized before acquisition wins; the model does not define rollback or
  revocation of an already finalized transition. Abandoned reservations, reusable counters, rate
  windows, refunds, and crash-durable storage need separate state-machine refinements.
- The bounded chain has exactly two delegation hops, two competing requests, one credential, one
  object, and one transition. It is not an induction theorem over unbounded chains, requests,
  objects, or epochs.
- The record-projection equations are subterm-convergent and expose fields intentionally used by
  protocol-state pattern matching. Signing-key records are never emitted to the network.
- No independent formal-methods review has been completed. The model, assumptions, and
  implementation correspondence require external review before a production-verification claim.

## Reproduction and gate construction

The authorization model has a dedicated two-phase gate because Tamarin's message-derivation check
is substantially more expensive than any individual lemma. The gate first runs an exact-source
preflight on the model bytes with Tamarin 1.12.0, `--open-chains=50`, derivation checking enabled,
and `--quit-on-warning`. It hashes the model before and after the preflight. Only after that succeeds
does one proof process select every name in
`formal/tamarin/activechain_authorization_chain.lemmas`; derivation checking is disabled only for
that second process because the identical model bytes already passed it once.

The gate rejects a changed hash, a warning, a failed wellformedness check, a falsified or incomplete
selected lemma, a missing lemma summary, or a non-zero prover exit. Run it with:

```sh
bash scripts/check-formal-models.sh
```

The default authorization preflight and proof process bounds are intentionally longer than the
other small Tamarin models. They may be overridden for diagnostics, but a release record must retain
the complete preflight and all eighteen verified summaries from a clean checkout.
