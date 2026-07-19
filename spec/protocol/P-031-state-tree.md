# P-031: Sparse state tree and witnesses

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/5>

## 1. Scope

This revision specifies the first canonical authenticated state commitment over P-030 objects and canonical single-key membership and non-membership witnesses. It deliberately uses a simple fixed-depth reference shape before production path compression and batch multiproofs are frozen.

Database persistence, compact multiproofs, deltas, leases, hibernation, snapshots, state sync, and transition-witness application are separate refinements. Storage engines MUST NOT reinterpret the root or proof rules defined here.

## 2. Key path and partitions

An `ObjectId` is a 384-bit tree key and therefore contains exactly 96 high-to-low nibbles. Depth zero consumes the high nibble of byte zero; depth 95 consumes the low nibble of byte 47. Every internal node has 16 ordered child positions.

The logical partition identifier is the first 12 key bits:

```text
partition_id = (object_id[0] << 4) | (object_id[1] >> 4)
```

It is in `[0, 4095]`. The first three tree levels therefore commit the 4,096 logical partition roots into one global tree root. Partitioning changes storage and proof scheduling, not consensus or authorization domains.

## 3. Reference tree shape

Version 1 uses an uncompressed 96-level sparse 16-way tree. A present key terminates in one object leaf. An absent key terminates in the canonical empty leaf. Internal nodes are never encoded as consensus objects; only their transcript hashes are committed.

The shape is independent of insertion order. Objects MUST already be strictly ordered and duplicate-free under `ObjectStateV1`. A node with all empty children has the canonical precomputed empty hash for its depth.

The reference shape prioritizes clarity and differential testing. A future path-compressed representation MAY replace physical nodes only if it provably yields the exact same logical root or activates under a new protocol version.

## 4. Hash transcript

Every hash is SHAKE256 with exactly 48 output bytes. Integers are unsigned big-endian. Concatenation below has no omitted fields:

```text
prefix  = ASCII("ACTIVECHAIN-STATE-TREE")
version = u16(1)

leaf(object) = SHAKE256/384(
    prefix || version || u8(0) || object_id ||
    u32(len(canonical_object_envelope)) || canonical_object_envelope
)

empty_leaf = SHAKE256/384(prefix || version || u8(1))

node(depth, children[16]) = SHAKE256/384(
    prefix || version || u8(2) || u8(depth) ||
    child[0] || ... || child[15]
)

state_root(object_count, tree_root) = SHAKE256/384(
    prefix || version || u8(3) || u64(object_count) || tree_root
)
```

`canonical_object_envelope` includes the P-001 type tag, schema version, minimally encoded body length, and body. The encoded length MUST fit `u32`; P-030 bounds make this mandatory for every valid object.

The empty subtree hash at leaf depth 96 is `empty_leaf`. For depth `d < 96`, it is `node(d, [empty[d+1]; 16])`. The canonical empty state commits `object_count = 0` and `empty[0]`.

## 5. State commitment

`StateCommitmentV1` contains the final 384-bit state root and exact `u64` object count. The final root transcript binds both the logical tree root and count. The explicit development state currently contains at most 64 objects, but the commitment format reserves the full count range for future witnessed global state.

Two conforming implementations given the same canonical object set MUST produce the same commitment regardless of construction history, storage layout, thread scheduling, or database iteration order.

## 6. Compressed single-key proof

A `StateProofV1` contains:

```text
kind: Membership | NonMembership
object_id
levels[96]
```

Each root-to-leaf level contains a 16-bit sibling bitmap and the listed non-default sibling hashes in ascending child-index order. The bit for the queried path child MUST be zero. A zero bit means the canonical empty subtree hash at the child depth. A one bit consumes exactly one 48-byte digest. The number of digests is therefore the bitmap population count; no redundant length is encoded.

A digest equal to the canonical empty child hash MUST be omitted and is rejected if explicitly encoded. These rules give every logical single-key proof exactly one version-1 representation.

The worst case contains all 15 siblings at all 96 levels and has a 69,361-byte body. Sparse development proofs are substantially smaller.

## 7. Proof generation and verification

Proof generation traverses the queried nibble path. At every level it hashes all non-empty sibling subtrees and omits canonical empty siblings. The proof kind is `Membership` exactly when the state contains the full object identifier.

Membership verification requires the separately supplied canonical object and checks that its identifier equals the proof identifier. Folding begins with `leaf(object)`. Non-membership verification requires the claimed absent identifier and begins with `empty_leaf`.

For depths 95 down to zero, verification reconstructs the 16 children from the path accumulator, explicit siblings, and depth-specific empty hash, then applies the internal-node transcript. It finally applies the state-root transcript using the committed object count and requires exact root equality.

Verification MUST reject:

- the wrong proof kind;
- a mismatched object identifier;
- a bitmap containing the path-child bit;
- sibling count different from bitmap population count;
- an explicitly encoded canonical empty sibling;
- an unsupported tag or schema;
- truncated or trailing data; or
- any final root mismatch.

## 8. Canonical types and bounds

```text
StateProofV1       type 0x0055, schema 1, max body 69,361 bytes
StateCommitmentV1  type 0x0056, schema 1, max body     56 bytes
```

Proof decoding performs exactly 96 bounded iterations. Every per-level allocation is bounded by 15 digests, and the total by 1,440 digests. Tree construction operates only on the bounded, canonical explicit object state in this revision.

## 9. Security and correctness properties

Security assumes SHAKE256 collision and preimage resistance at 384-bit output. Object membership authenticates the complete canonical object envelope, including its version and policies. The object count is bound by the final root but a single proof does not reveal other keys.

Required executable properties are:

```text
same object set in any construction order -> same root
changing any object field                -> different root, absent a hash collision
valid member proof                       -> verifies only for that object and commitment
valid absence proof                      -> verifies only for that key and commitment
any sibling, bitmap, key, kind, or leaf tamper -> verification failure
first 12 key bits                         -> one deterministic partition in [0,4095]
```

## 10. Formal model and vectors

The Lean reference model fixes high-to-low nibble extraction and 16-way bottom-up proof folding over an abstract hash function. Rust differential fixtures cover boundary keys and path order. Frozen state-tree vectors publish an empty commitment, a multi-object commitment, a membership proof, and a non-membership proof with their canonical envelopes and verification results.

## 11. Compatibility

Changing path order, arity, depth, transcript prefix, transcript version, node kind, integer encoding, object envelope inclusion, empty-root derivation, proof bitmap meaning, or final count binding changes historical roots and requires a new protocol/schema version. Physical storage optimizations MUST remain semantically invisible.

## 12. Implementation notes (non-normative)

The safe-Rust `no_std` reference implementation uses bounded recursion of at most 96 levels over at most 64 explicit objects. It is a correctness oracle and benchmark baseline, not yet the production persistence engine.
