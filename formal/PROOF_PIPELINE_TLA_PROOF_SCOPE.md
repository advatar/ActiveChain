# ActiveChain proof-carrying block pipeline TLA+ proof scope

Status: bounded safety model exhaustively checked with no invariant or action-property violation.
This is not a refinement proof of the Rust node, proof system, scheduler, or reward implementation,
and it is not whole-protocol certification.

`formal/tla/ActiveChainProofPipeline.tla` is an executable model of the proof-carrying block path
between deterministic execution and finalized state. It makes the proof job queue and verifier
boundary explicit, including hostile prover behaviour and stale proof delivery.

## Bounded model

The finite universe contains:

- two sequential block heights and revisions;
- two competing canonical order batches at height one and one continuation for each resulting
  state at height two;
- a total deterministic execution function from exact pre-state, canonical order batch, and block
  revision to post-state;
- a two-job queue and one active-prover slot, making backpressure executable;
- two attempts per job, with retry and terminal exhaustion;
- an honest prover, a dishonest prover, a failing prover, and a withholding prover;
- one valid and one invalid proof per job, plus a malformed proof;
- arbitrary dishonest submission of every proof to every job, which explores valid cross-job
  replay across order sets, states, heights, and revisions;
- explicit verification acceptance and rejection, withholding timeout, stale-job cleanup,
  duplicate proof delivery, finalization, and reward accounting; and
- finalization only when the job still extends the current finalized head.

The public input compared at the verifier boundary is the exact record:

```text
{ height, pre-state, canonical order batch, post-state, block revision }
```

The post-state must equal deterministic execution of the other public inputs. Both cryptographic
validity for a proof's own input and equality with the target job's entire input are required.

Using TLA+ tools v1.8.0, TLC completed exhaustive breadth-first exploration with:

```text
58,469 states generated
15,664 distinct states found
0 states left on queue
complete-state-graph depth 28
```

No invariant or temporal action-property violation was found. These counts use the runner's
deterministic single-worker default; `ACTIVECHAIN_TLC_WORKERS` may override it. The runner also
emits action coverage: every modeled transition was enabled during exploration, including proof
rejection and withholding timeout. Some of those transitions lead to an already-known failed-job
state, which TLC reports as a generated but non-distinct successor.

## Checked safety properties

The TLC configuration checks that:

- queue and active-prover capacity are never exceeded;
- assigned prover, submitted proof, accepted proof, and attempt state remain coherent;
- no invalid, malformed, or mismatched proof is accepted;
- a valid proof for another order batch, pre-state, height, or revision cannot be replayed into a
  target job;
- every finalized block names a verifier-accepted proof whose public input binds the exact
  pre-state, order batch, deterministic post-state, height, and revision;
- finalization history is sequential, has at most one block per height, and reconstructs the exact
  deterministic finalized state;
- failure, withholding, timeout, retry, rejection, duplicate delivery, and stale cleanup cannot
  mutate finalized state or history;
- rewards can change only during finalization, are paid only for that block's accepted proof, and
  cannot be paid twice for duplicate proof delivery; and
- every finalized proof is rewarded exactly once.

The reproducible command is:

```sh
bash scripts/check-tla-proof-pipeline.sh
```

The runner pins TLA+ tools v1.8.0 by SHA-256
`cc4803dce2a8ffaf0f5920a9dc39df4b5ee34ab4cb53fb58ac557277a7e516b3` and runs it with Eclipse
Temurin 21.0.8 using OCI image digest
`sha256:db1689535962d757a5adabf57387584ed543d38c0b9d1fe870123ea362ad73b0`.

## Refinement contract

The safety result applies to production only after the implementation establishes all of these
correspondences:

| Model boundary | Required implementation behaviour |
| --- | --- |
| canonical order batch | Decode one versioned canonical order-set encoding, reject duplicates and trailing bytes, and bind its commitment into the block. |
| deterministic execution | Re-execution of the same pre-state, order batch, and revision must produce the same post-state or fail closed. |
| proof job | Persist the complete public-input record before dispatch and use an immutable job identifier derived from it. |
| verifier | Verify proof bytes and compare every public-input field with the persisted job using canonical equality. No field may be caller-supplied after verification. |
| retry and timeout | Retries must preserve the same job input; a timeout may release capacity but may not mutate state or reward accounting. |
| finalization | Recheck the job against the current finalized head and active revision atomically with committing the new state. |
| duplicate handling | Store a durable proof/job acceptance key so replay cannot finalize or reward twice after restart. |
| reward | Pay only the unique proof attached to the finalized block, in the same atomic state transition or a replay-safe derived transition. |

## Explicit assumptions and exclusions

- `CryptographicallyValid` abstracts sound proof verification. STARK soundness, hash collision
  resistance, PQ assumptions, verifier implementation correctness, and proof-byte canonicality are
  external assumptions.
- The state, order batches, revisions, queue, attempts, and heights are finite. Exhaustive means all
  interleavings in this universe, not all production values or unbounded executions.
- The model treats the committed order batch as available. Data availability sampling, erasure
  recovery, censorship, ordering consensus, and state-sync proof verification are separate models.
- Crashes and durable restart recovery are not modeled in this slice. The refinement must persist
  jobs, accepted proof identities, finalized state, and reward replay protection atomically.
- Prover selection economics, stake/slashing, fee calculation, proof aggregation/recursion, and
  multi-proof block policies are outside this safety result.
- A block has one required execution proof. Optional privacy proofs, authorization proofs, DA
  proofs, and consensus QCs must be composed and bound separately before the complete block is
  admitted.

## Liveness is intentionally excluded

`Spec` has no weak fairness, strong fairness, delivery, honest-prover availability, or synchrony
assumption. A prover may withhold forever, all attempts may fail, a queue slot may be starved, and
the bounded pipeline may terminate without finalizing. Checking eventual finalization would be
dishonest without additionally assuming that a compatible job is enqueued, an honest prover is
eventually assigned, its proof is delivered, verification runs, and finalization is scheduled.
This artifact therefore proves no throughput, latency, availability, censorship resistance, or
eventual-finalization property. A separate fair/timed liveness model is required for those claims.
