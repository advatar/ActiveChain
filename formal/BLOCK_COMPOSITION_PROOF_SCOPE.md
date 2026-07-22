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

## Rust conformance implementation

Issue #37 added the authoritative Rust types and admission path for this composition predicate.
The original gaps are retained below as the implementation checklist now covered by
`consensus-runtime::finalized_block` and `consensus-runtime::proof_pipeline`:

1. Strictly decode and re-encode the canonical `DevnetBlock` before deterministic execution.
2. Materialize `ProofPublicInputs` and `FinalizedBlockHeader`; the typed proposal entry point derives
   the only voteable digest from that header.
3. Compose `devnet-kernel::apply_block` output into the exact receipt, economics, post-state, and
   header digest checked at admission.
4. Require a finalized authorization-verifier observation for every action and recompute the
   canonical authorization aggregate.
5. Recompute DA and receipt commitments from canonical bytes and bind both to the QC header.
6. Reconstruct execution-proof public inputs and require the selected proof verifier to accept the
   exact statement commitment.
7. Crash-atomically publish proof finality, executed state, locks/nonces/tickets, fee/supply result,
   DA/proof/header metadata, and finalized block digest in `DurableFinalizedState`.
8. Freeze the header vector and reject authorization/action/order/receipt/state/DA/revision
   substitution, cross-job proofs, replay, corruption, backpressure, and duplicate rewards.
9. Keep cryptographic soundness and collision resistance as explicit assumptions; the Rust path
   enforces the same concrete equality and strict-codec premises used by the Lean theorem.

The concrete boundary now recomputes these bindings and rejects mismatch before materializing a
`FinalizedBlock`. Cryptographic authorization, execution-proof, and weighted-QC soundness remain
explicit verifier observations, matching the abstraction boundary of the Lean model.

## Local reproduction

```bash
cd formal/lean
lake env lean ActiveChain/BlockComposition.lean
lake build
```

Acceptance also requires a source scan confirming that the module contains no proof placeholders
or newly declared logical shortcuts.
