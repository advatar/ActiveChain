# P-030: Object model, ownership, versioning, and access

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/4>

## 1. Scope

This revision specifies the first canonical object, explicit object-version references, bounded access manifests, and a basic atomic transfer transition. It is the executable object refinement used before the authenticated state tree and ObjectVM exist.

State-tree paths and roots, hibernation, creation commands, dynamic-read execution, package execution, fees, capability-budget settlement, and arbitrary contract mutation are separate refinements. Their reserved fields are encoded now only where this revision can validate them unambiguously.

## 2. Canonical object

`ObjectV1` contains:

```text
object_id, object_version, type_id, owner,
control/use/disclosure/upgrade policy commitments,
optional package_id, value_root, optional public_value,
lease_expiry_epoch, storage_deposit, flags
```

The owner is exactly one of `Principal`, `Shared`, `Immutable`, `CapabilityControlled`, or `Shielded`. A principal or capability owner carries its typed identifier. A shielded owner carries only a commitment.

The optional public value is bounded to 16,384 bytes. Its interpretation is fixed by `type_id` and, when present, `package_id`. `value_root` commits to the authoritative value representation; this revision does not recompute application-specific value commitments.

## 3. Object flags

Version 1 registers three bits:

```text
0x0001 TRANSFERABLE
0x0002 LINEAR
0x0004 SYSTEM
```

Every other bit MUST be zero. `LINEAR` and `SYSTEM` are commitments for later VM and protocol rules; basic transfer does not reinterpret them. An `Immutable` object MUST NOT carry `TRANSFERABLE`.

## 4. Versioning

Every mutable operation consumes an exact reference `(object_id, expected_version)`. A successful transfer creates the same object identifier at exactly `expected_version + 1` using checked `u64` arithmetic. A stale reference or version exhaustion fails without an update.

A transfer changes only `owner` and `object_version`. It MUST preserve type, all policy commitments, package, value root and bytes, lease, storage deposit, and flags. A transfer to the current owner is rejected as a non-canonical no-op. `Immutable` objects and objects without `TRANSFERABLE` cannot be transferred. Basic transfer also cannot create an `Immutable` destination; immutable publication requires a later dedicated finalization command that can clear transferability canonically.

No successful version-1 transfer preserves, decreases, or skips the object version.

## 5. Access manifest

`AccessManifestV1` declares:

```text
exact_reads             <= 64 ObjectVersionRef values
exact_writes            <= 32 ObjectVersionRef values
immutable_reads         <= 64 ObjectId values
creation_namespaces     <= 16 NamespaceGrant values
maximum_created_objects <= 16
maximum_dynamic_reads   <= 32
dynamic_read_policy     Option<Digest384>
```

Each collection MUST be strictly increasing and duplicate-free. Exact collections are ordered by object identifier and cannot contain two versions of one object. Exact reads, exact writes, and immutable reads MUST be pairwise disjoint by object identifier. A write implicitly reads the consumed version.

Namespace grants pair a canonical `ResourceSelector` with the capability authorizing creation. They are ordered by their canonical selector and capability identifier. Version 1 requires no creation namespaces when the maximum creation count is zero and at least one when it is non-zero.

`maximum_dynamic_reads = 0` requires no dynamic-read policy. A positive maximum requires a policy commitment. Basic transfer executes neither object creation nor dynamic reads, but preserves these declarations for forward-compatible charging and later commands.

## 6. Basic transfer transaction

A `TransferTransactionV1` contains a deterministic block height, one access manifest, and between one and 32 transfer commands. Commands MUST be strictly increasing by input object identifier.

Each command contains:

```text
input: ObjectVersionRef
new_owner: ObjectOwner
control_policy: PolicySetV1
request: PolicyRequestV1
```

The registered transfer action identifier is the 384-bit big-endian integer one (`00` repeated 47 times followed by `01`). A command request MUST bind the transaction height, registered action, and exact input object.

## 7. Authorization and validation order

Commands execute in canonical list order. The first failing check determines the receipt:

1. request height, action, and resource binding;
2. exact input reference in `manifest.exact_writes`;
3. object existence in the explicit pre-state;
4. exact object version;
5. canonical commitment of `control_policy` equals the object's `control_policy_hash`;
6. APL evaluation returns `Permit`;
7. the APL decision has no obligations unsupported by this transfer refinement;
8. object mutability, transfer flag, owner change, and checked next version.

The request's authentication, credentials, capabilities, and approvals remain pre-verified facts under P-023. The transition MUST NOT manufacture or broaden them.

## 8. Atomic transition

The reference transition receives a canonical `ObjectStateV1` containing at most 64 objects sorted strictly by identifier. It applies successful commands to scratch state.

If every command succeeds, all updated objects become the post-state. If any command fails, scratch state is discarded and the complete canonical pre-state is returned. A failed receipt reports zero updated objects even if earlier scratch commands succeeded. There is no partial state publication.

The transition reports accumulated APL steps up to and including the failing command. The maximum is 17,408 steps. This work count is deterministic for a given validated input.

## 9. Receipts

`TransitionReceiptV1` records:

- success or one typed semantic failure;
- optional zero-based failed-command index;
- published object-update count;
- APL steps used;
- canonical pre-state and post-state commitments.

Success has no failed index and updates exactly the non-empty command count. Failure has a failed index, zero published updates, and equal pre/post commitments. Semantic outcomes are `Success`, `RequestContextMismatch`, `AccessManifestViolation`, `ObjectNotFound`, `StaleObjectVersion`, `ControlPolicyMismatch`, `AuthorizationDenied`, `UnsupportedObligation`, `ImmutableObject`, `TransferDisabled`, `OwnerUnchanged`, and `VersionExhausted`.

An inability to encode a structurally valid state commitment is an implementation-level transition error, not a semantic receipt and MUST NOT be interpreted as success.

## 10. Canonical top-level values and bounds

```text
ObjectV1               type 0x0050, schema 1, max body    16,856 bytes
AccessManifestV1       type 0x0051, schema 1, max body    10,093 bytes
TransferTransactionV1  type 0x0052, schema 1, max body 1,265,334 bytes
TransitionReceiptV1    type 0x0053, schema 1, max body       104 bytes
ObjectStateV1          type 0x0054, schema 1, max body 1,078,785 bytes
```

All collection lengths are checked before proportional allocation. Unknown flags, invalid owner/flag combinations, oversized public values, unordered or overlapping access declarations, ambiguous limit/policy pairs, empty or unordered command batches, inconsistent receipts, duplicate state objects, unsupported tags, and trailing bytes are rejected canonically.

## 11. Formal properties and vectors

The executable Lean model fixes one-step version consumption and atomic batch publication. Required properties are:

```text
successful transfer: post.version = pre.version + 1
failed batch:         published_state = pre_state
successful batch:    published update count = command count
```

Frozen vectors include the object, manifest, transaction, success receipt, and post-state, plus a cross-implementation version/atomicity table. Property tests range over every non-exhausted `u64` version and require exact one-step advancement; failure tests mutate each semantic dimension and require byte-identical pre/post state.

## 12. Compatibility

New owner kinds, flags, commands, receipt outcomes, or access forms require unused discriminants and an appropriate schema/protocol version. Historical versions, validation order, action identifiers, and error selection MUST NOT be reinterpreted.

## 13. Implementation notes (non-normative)

The Rust object and transition crates are safe, `no_std`, and allocate only schema-bounded vectors. `ObjectStateV1` is an explicit semantic fixture, not the production global-state format; P-031 will replace its linear lookup boundary with authenticated state witnesses while preserving P-030 object behavior.
