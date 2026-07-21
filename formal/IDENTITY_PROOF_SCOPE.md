# ActiveChain identity and capability proof scope

`formal/tamarin/activechain_identity.spthy` is an executable, bounded symbolic model of the
principal/DID lifecycle and one direct capability-delegation decision described by P-020, P-022,
and P-095. It is intended to make the security boundary and current proof claims precise. It is not
a claim that the entire identity implementation, cryptographic provider, or network has been
formally verified.

## Proven trace properties

Tamarin proves the following properties over every trace admitted by this model:

- every observed lifecycle transition retains `did(principal_id)`, so controller rotation,
  recovery, freeze, and deactivation cannot change the stable DID;
- controller rotation requires a prior authorization bound to the current principal, sequence,
  controller, operation, command, and proposed controller;
- recovery initiation requires a prior recovery-authority result at the exact principal sequence;
- recovery completion requires both its matching initiation and a challenge-deadline event;
- at most one lifecycle transition can consume a principal sequence, including when serialized
  command bytes are replayed;
- deactivation is terminal: no later lifecycle transition exists for the principal;
- every direct delegated capability is constructed by restricting each version-1 authority
  dimension and exactly inheriting the opaque constraint and revocation registry;
- a revoked parent cannot be delegated after revocation;
- a revoked capability cannot be used after revocation; and
- one invocation identifier cannot be accepted twice, even though its public invocation bytes can
  be replayed by the Dolev-Yao environment.

The theory also includes executable traces for controller rotation, completed recovery,
deactivation, delegated capability use, and delegated capability revocation. Those witnesses
prevent universal safety lemmas from passing merely because the relevant operation is unreachable.

## Model-to-implementation correspondence

The phase-specific linear principal facts correspond to current canonical principal state at
sequences `s0` through `s3`. Competing operations consume the same phase fact, modeling the checked
one-step sequence consumption in `activechain-principal`. This finite unrolling covers rotation,
freeze followed by recovery, recovery from active, completed recovery, and deactivation after
creation or rotation. It does not establish an induction theorem for arbitrarily many rotations.
A `LifecycleAuthorization` corresponds to the private, preverified Rust authorization fact: it is
bound to authority kind, principal, sequence, current authority, command, and proposed update, and
it is consumed exactly once.

The model's controller and recovery authorization rules represent successful authentication and
policy evaluation upstream of the lifecycle kernel. This matches P-020's explicit trust boundary;
it does not prove the ML-DSA implementation or APL evaluation itself.

Capability authority is modeled as this ordered tuple:

```text
actions, resource scope, data scope, monetary limit, compute limit,
rate limit, use limit, valid-from, valid-until, delegation depth,
constraint commitment
```

A child can be created only with `subset_*`, `lower_*`, `later_start`, `earlier_end`, and
`lower_depth` constructors over the parent's values. The constraint is unchanged and the same
revocation registry is carried into the child. This mirrors the checks in
`activechain-capability::verify_attenuation`. The model follows one root-to-child delegation and
one prepared child invocation so that revocation and replay are checked without assuming an
unproved recursive invariant.

## Assumptions

- Protocol constructors are free and domain separated; identifiers and fresh command/invocation
  values do not collide.
- The consensus state machine provides atomic consumption of linear principal, authorization,
  capability-status, recovery-request, and invocation-permit facts.
- Only authenticated policy evaluation creates controller/recovery authority facts.
- `subset_actions`, `subset_scope`, `lower_limit`, `lower_rate`, `later_start`, `earlier_end`, and
  `lower_depth` have the narrowing meanings required by P-022. Tamarin treats these as symbolic
  constructors rather than proving their arithmetic or bit-prefix semantics.
- A capability use checks the current capability status and consumes a unique invocation permit.
- The recovery challenge-deadline event is emitted only after the required finalized height.

## Explicit gaps and required refinements

- The Rust principal crate currently implements creation, rotation, freeze, and recovery
  initiation. Recovery challenge/cancellation/completion and deactivation are P-095 requirements
  modeled here but still require canonical commands and implementation before the model can be a
  full refinement of executable code.
- ML-DSA/SLH-DSA unforgeability, ML-KEM secrecy, key compromise, recovery-policy compromise, and
  cryptographic agility are not proved in this theory.
- The Tamarin model starts at the preverified authorization boundary. A later composed model must
  connect signatures, APL evaluation, credentials, approvals, and state-root binding to creation of
  each authorization fact.
- The exact P-022 selector and numeric attenuation relations remain Rust/Lean refinement
  obligations. The symbolic constructor discipline proves that no unchecked authority dimension
  appears in a child, not that a particular integer or bit prefix is mathematically smaller.
- The lifecycle is a finite `s0`-to-`s3` unrolling. Arbitrarily long sequences of rotation,
  recovery, and deactivation require an inductive state-machine proof or an equivalent supporting
  invariant.
- The capability slice covers one direct delegation and one prepared invocation. Reusable grants,
  multiple children, multi-hop attenuation, rate/use-budget evolution, and interleavings among
  multiple live invocation permits require a larger inductive model.
- Parent revocation prevents future direct delegation, but recursive authorization-chain traversal,
  ancestor revocation, mutable shared budgets, registry membership proofs, and private-holder
  delegation proofs are outside this direct-delegation model.
- Deactivation is modeled as controller-authorized from `Active`. The final DID method specification
  must freeze whether frozen or recovery-pending principals have a deactivation path.
- Network reordering and replay are modeled symbolically; consensus forks, finality failures,
  validator-set changes, storage rollback, and denial of service are covered by separate models.
- No independent formal-methods review has been completed. Proof scripts, assumptions, and the
  implementation correspondence require external review before a production-verification claim.

## Reproduction

With Tamarin Prover 1.12 or later installed:

```sh
tamarin-prover formal/tamarin/activechain_identity.spthy \
  --derivcheck-timeout=60 --quit-on-warning --prove
```

On Tamarin 1.12.0 this command completed successfully with all wellformedness checks passing, ten
all-traces safety lemmas verified, and five exists-trace executability witnesses verified. The
release gate must run the proof from a clean checkout and retain the complete Tamarin summary as CI
evidence.
