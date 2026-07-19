# P-022: Capabilities, delegation, and revocation

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/2>

## 1. Scope

This revision specifies canonical capability grants and the conservative mechanical verifier for direct parent-to-child delegation. Mutable budget objects, signature verification, revocation witnesses, private-holder delegation proofs, and full authorization-chain traversal are separate refinements.

## 2. Canonical grant

`CapabilityGrantV1` contains:

- stable capability identifier, issuer, holder binding, and optional direct parent;
- a non-empty, sorted, duplicate-free set of at most 32 action identifiers;
- resource and data selectors;
- optional monetary, compute, rate, and use limits;
- validity interval;
- explicit delegation flag and remaining depth;
- optional revocation registry;
- immutable constraint commitment;
- suite-tagged issuer signature.

`None` for a numeric limit means unbounded. A grant with `delegation_allowed = false` MUST have zero remaining depth. A grant with delegation enabled MUST have positive remaining depth. A grant cannot name itself as parent.

## 3. Holder binding

Bindings are `Principal`, `Private`, or explicitly `Bearer`. Version 1 delegation requires the parent holder to be a public principal and the child issuer to equal that principal. A child MAY bind a different public principal or private commitment. A delegated bearer child MUST be rejected.

Root bearer grants are representable but wallets SHOULD warn prominently and policies MAY forbid them.

## 4. Selectors

A selector is `Any`, `Exact(Digest384)`, or `Prefix(bits, bytes)`.

- `Any` is the unique zero-bit prefix representation.
- `Exact` is the unique 384-bit representation.
- `Prefix` MUST contain between 1 and 383 significant high-order bits.
- Every bit outside the declared prefix MUST be zero.

An exact selector is contained by an equal exact selector or a matching prefix. A child prefix is contained by a parent prefix when it has at least as many significant bits and matches every parent bit. Every selector is contained by `Any`.

## 5. Attenuation equation

A child is accepted only if all predicates hold:

```text
parent.delegation_allowed
child.parent_capability = parent.capability_id
child.capability_id != parent.capability_id
parent.holder = Principal(child.issuer)
child.holder != Bearer
child.actions subset_of parent.actions
child.resource_scope subset_of parent.resource_scope
child.data_scope subset_of parent.data_scope
child.monetary_limit <= parent.monetary_limit
child.compute_limit <= parent.compute_limit
child.use_limit <= parent.use_limit
child.valid_from >= parent.valid_from
child.valid_until <= parent.valid_until
child.delegation_depth_remaining < parent.delegation_depth_remaining
child.constraint_hash = parent.constraint_hash
child inherits a parent revocation registry when one exists
```

For optional finite limits, a finite parent requires a finite child no larger than it. An unbounded parent permits either an unbounded or finite child.

## 6. Rate limits

A finite parent rate requires a finite child with the exact same block-window length and no greater maximum-use count. Version 1 deliberately rejects comparison across different windows because a simple average-rate comparison does not prove equal burst authority.

## 7. Constraints and revocation

An opaque constraint hash cannot prove that a new expression is a conjunction of old and new restrictions. Version 1 therefore requires exact inheritance. A future typed constraint algebra MAY permit mechanically proven conjunction.

If the parent names a revocation registry, the child MUST name the same registry. If the parent has no registry, adding one is an additional restriction and is allowed.

## 8. State-machine pseudocode

```text
verify_attenuation(parent, child):
    check delegation, parent reference, identifiers, and holder binding
    check action, resource, and data subsets
    check every optional budget and validity bound
    check strict depth reduction
    check immutable constraint and revocation inheritance
    return Permit only if every check passes
```

The function does not verify signatures. Authorization MUST intersect successful attenuation with valid issuer signatures, current budgets, revocation status, credentials, policies, approvals, and explicit forbids.

## 9. Errors and abort behavior

The verifier returns the first typed failed dimension and no partial authority. It MUST reject any relation it cannot mechanically prove narrower. Failure MUST NOT consume a budget or create the child grant.

## 10. Resource bounds

Action subset checking is bounded by 32 actions. Selectors are at most 51 bytes. Keys, signatures, and the entire capability body are length-bounded before allocation. `CapabilityGrantV1.MAX_ENCODED_LEN` is 22,024 bytes.

## 11. Security assumptions

Successful attenuation alone does not authenticate the issuer, establish holder control, prove non-revocation, or reserve mutable budgets. Those predicates remain mandatory in the complete authorization intersection.

## 12. Test vectors and formal properties

Authority vectors contain a parent and accepted child plus commitments. Unit tests mutate every authority dimension and require the corresponding rejection. Property tests range over numeric limits and MUST establish:

```text
verify_attenuation(parent, child) = Permit
implies child authority is no broader under the version-1 algebra
```

A future Lean model MUST prove the subset relation transitive for supported selectors and limits.

## 13. Compatibility

New selector forms or attenuation relations require a new schema or protocol version. A future version MAY accept more provably safe relations but MUST NOT reinterpret a version-1 child previously rejected as valid under historical verification.

## 14. Implementation notes (non-normative)

The Rust attenuation crate is `no_std`, has no cryptographic provider dependency, and deliberately uses a small explicit error enum suitable for differential testing.
