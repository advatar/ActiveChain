# Canonical finalized-block composition proof scope

Status: development proof model; not end-to-end Rust refinement or production certification.

`formal/lean/ActiveChain/BlockComposition.lean` defines one fail-closed finalization boundary for a
canonical block. It prevents consensus, execution, economics, state, data availability, and proof
verification from accepting mutually unrelated objects which happen to be presented together.

## Mechanically checked properties

Lean checks that every successful finalization has all of these bindings at the same time:

- the complete input envelope strictly decodes and exactly re-encodes, with the expected type tag
  and schema version;
- the header carries the exact expected chain ID, protocol revision, epoch, validator-set root,
  height, parent digest, pre-state root, and pre-supply;
- the authorization result is the deterministic result for that context and decoded action list,
  covers every action with an allow decision, and matches the header authorization commitment;
- execution is the deterministic result for those same actions and authorization result, executes
  exactly the decoded actions, and supplies a complete, unique, in-range action order;
- action and order roots match the executed values;
- fee charging and the supply transition match the header and satisfy the subtraction-free supply
  equation, with fee burn bounded by fees charged;
- the committed post-state root is computed from the execution result;
- the availability payload is the deterministic encoding of the same context, actions,
  authorization, and execution result, and its commitment matches the header;
- the execution-proof statement uses public inputs reconstructed from that exact header, its
  statement commitment matches the header, and the supplied proof passes the verifier boundary;
  and
- the quorum certificate repeats the header chain/revision/epoch/set/height context, verifies at
  the certificate boundary, and certifies the commitment of that exact header.

The model also checks rejection theorems for a non-canonical envelope, wrong schema or protocol
revision, wrong chain context, authorization mismatch, action/order-root mismatch, invalid or
mismatched economics, post-state mismatch, DA mismatch, proof-input or proof-statement mismatch,
and a QC-certified digest mismatch. A general theorem rejects the candidate when any one of the
seven binding groups fails.

Finalization is a function and therefore produces one result for one accepted candidate. A
stronger theorem checks that two successful candidates carrying the same complete canonical
envelope materialize the same finalized block when proof-statement commitments are injective.
Proof bytes are intentionally excluded from block identity because multiple valid proof byte
strings may establish one statement.

Finally, Lean checks two explicit collision-conditional uniqueness results:

- under post-state and proof-statement commitment injectivity, two accepted candidates with the
  same header cannot expose different post-states or proof statements; and
- under header, post-state, and proof-statement commitment injectivity, equality of two
  QC-certified block digests yields the same result.

There are no unchecked proof placeholders or globally introduced logical assumptions in this
module.

## Assumptions and abstraction boundary

The uniqueness theorems take every injectivity property they use as a named theorem premise:

- canonical encoder injectivity is needed only when deriving wire-block equality from equal
  encodings without using the deterministic strict decoder;
- header-commitment injectivity is needed when deriving header equality from equal certified
  digests;
- post-state commitment injectivity is needed when deriving state-byte equality from equal state
  roots; and
- proof-statement commitment injectivity is needed when deriving statement equality from equal
  statement commitments.

These premises abstract collision/second-preimage resistance and domain separation. Lean does not
claim SHAKE256 is mathematically collision-free. Production safety requires concrete domains,
length framing, and algorithm identifiers for every commitment.

Other explicit refinement boundaries are:

- `CanonicalCodec` abstracts the Rust envelope decoder and encoder. The strict wrapper rejects any
  decoder output whose canonical re-encoding is not every supplied byte, but the Rust codec still
  needs conformance tests or bounded proofs for cursor consumption, size limits, minimal lengths,
  field coverage, integer conversion, and schema dispatch.
- `authorize` and `execute` are deterministic protocol functions. This model composes their
  results; their internal APL, ObjectVM, native-cash, concurrency, and state-tree semantics need
  separate refinement.
- `verifyExecutionProof = true` abstracts sound verification by the selected PQ execution-proof
  system. This model proves exact public-input binding after that observation, not proof-system
  soundness or prover completeness.
- `verifyQuorumCertificate = true` abstracts the weighted PQ finality verifier. Consensus quorum,
  locking, validator-set, crash-recovery, and chain-prefix arguments live in the consensus proof
  slices.
- Natural numbers abstract checked bounded Rust integers. Rust must reject overflow in resource,
  fee, issuance, burn, height, epoch, and revision arithmetic.
- The supply equation permits declared issuance. Separate economics authorization must prove that
  the issuance field came from the unique finalized issuance transition and has not been redeemed
  before.
- The model proves safety, not block production, proof generation, DA retrieval, network liveness,
  or validator availability.

## Rust conformance gaps

The repository currently has useful components, but no authoritative Rust type and admission path
implements this complete composition predicate:

1. `consensus-runtime::CertifiedBlock` certifies an opaque `Digest384`. It does not decode a
   canonical block and recompute that digest from the action batch, execution receipt, economics,
   post-state, DA commitment, and proof statement before finality is applied.
2. `protocol-types::BlockProposal` carries epoch/height/round and an opaque digest, while the
   proposal signing payload does not itself expose the parent, pre-state, protocol revision,
   validator-set root, execution commitments, or proof public inputs as one typed block header.
3. `devnet-kernel::apply_block` provides a deterministic action/state/fee receipt path, but its
   `BlockOutput` is not yet composed into the exact header digest voted on by
   `consensus-runtime`.
4. `action-kernel::ActionEnvelope` carries an authorization commitment, but block admission still
   needs a finalized authorization result for every action and a canonical aggregate commitment
   which is checked before execution.
5. The DA batch and receipt roots are not yet bound into the same typed header whose digest receives
   the QC. A validator must recompute DA commitment bytes from the canonical block payload rather
   than accept a caller-declared digest.
6. There is no production execution-proof statement/verifier path whose public inputs are
   reconstructed from chain context, action/order roots, economics, post-state, and DA commitment.
7. There is no atomic durable commit which publishes the QC, executed state, input locks/nonces,
   fee/supply accounting, DA metadata, and proof result together, or rolls them all back together
   after a crash.
8. Cross-crate conformance vectors do not yet mutate each individual binding and establish that the
   authoritative validator path rejects every mismatch before voting and again before applying a
   received certificate.
9. The concrete hash/codec refinements needed by the collision-conditional theorems have not yet
   been connected to the domain-tagged Rust implementations with trace-equivalence or exhaustive
   bounded checks.

Until these gaps are closed, the result should be described as a mechanically checked canonical
block-composition contract, not as proof that the current node finalizes executed blocks correctly.

## Local reproduction

```bash
cd formal/lean
lake env lean ActiveChain/BlockComposition.lean
lake build
```

Acceptance also requires a source scan confirming that the module contains no proof placeholders
or newly declared logical shortcuts.
