# Data availability and light-client proof scope

`formal/lean/ActiveChain/DA.lean` is a dependency-free Lean 4 safety model for the bounded
data-availability kernel and the network-disabled light-client trust boundary described by P-110.
It is a scoped protocol model, not a proof that the complete Rust node or dBrowser implementation is
correct.

## Mechanically checked properties

Lean checks, without `sorry`, `admit`, or added axioms, that:

- shard verification accepts exactly when every shard is bound to its position-indexed commitment,
  and unequal shard/commitment list lengths are rejected;
- an explicit first commitment mismatch is rejected;
- accepted samples have the requested non-zero cardinality, stay at or below the total shard count,
  contain no duplicate index, and contain only indices below the declared shard count;
- accepted reconstruction evidence has positive shard sizes bounded by one MiB, positive payload
  length bounded by the data-shard capacity, no duplicate missing indices, and an erasure count at
  or below the parity-shard budget; it supplies the complete restored shard set at the declared
  shard size, passes every indexed shard commitment, and binds the extracted payload to the
  expected payload commitment;
- a light-client head advances only to a strictly greater height after all P-110 classes of evidence
  are present: finalized QC binding, active validator-set authorization, checkpoint binding, state
  proof, data-availability proof, and protocol-revision authorization;
- absent data-availability evidence fails closed; and
- validator-set or protocol-revision changes require finalized evidence at the candidate activation
  height, bound to both the previous and next values.

## Implementation mapping

| Model element | Current implementation/specification boundary |
| --- | --- |
| `Layout.Valid`, erasure budget | `AvailabilityBatch::{encode,deserialize,reconstruct}` bounds in `crates/data-availability/src/lib.rs` |
| `verifyCommitments` | indexed `ACTIVECHAIN-DA-SHARD-V1` SHAKE256 checks during deserialize and reconstruction |
| `restoredPayload` | concatenation of restored data shards followed by `payload_len` truncation |
| payload binding | `ACTIVECHAIN-DA-PAYLOAD-V1` commitment and `availability-v1.txt` fixture |
| `verifySamples` | non-empty, bounded sampling obligation; deterministic index derivation remains a Rust/vector refinement |
| `verifyTrustTransition` | P-110 light-client requirements and `testing/vectors/light-client-v1.json` |

## Explicit assumptions and unproved boundary

- SHAKE256 collision and second-preimage resistance are assumed cryptographic properties. The Lean
  model proves equality of recomputed commitments, not injectivity of SHAKE256.
- Correctness of `reed-solomon-erasure` over its Galois field, including recovery of the originally
  encoded payload from any permitted erasure pattern, is a library/refinement obligation. The Lean
  model proves that a claimed restored set cannot be accepted without the complete commitment and
  payload checks.
- The Rust implementation must refine the model's unbounded naturals using checked integer
  conversions and its published memory limits.
- The current Rust `sample` function can reject duplicate XOF outputs with `SampleCollision`; this
  model verifies the resulting sample set but does not formalize SHAKE256 XOF distribution or
  probabilistic availability guarantees.
- `qc.valid`, state-proof validity, and finalized change evidence are trusted observations supplied
  by their respective verified kernels. Consensus authentication and trace properties belong to the
  separate Tamarin consensus model.
- Availability sampling alone does not prove global retrievability against every withholding
  strategy. A production theorem needs an explicit adversary, sampling probability, peer diversity,
  and network-timing model.
- The model does not establish liveness, implementation memory safety, FFI correctness, deployment
  correctness, or an end-to-end dBrowser trust implementation.

## Local reproduction

```bash
cd formal/lean
lake env lean ActiveChain/DA.lean
```

Acceptance requires a successful Lean run and no occurrence of `sorry`, `admit`, or `axiom` in the
model.
