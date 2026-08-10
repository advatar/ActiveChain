I inspected the current `main`, the frozen #772 contract, and the active implementation in [PR #782 / issue #776](https://github.com/advatar/ActiveChain/pull/782), plus the dependent [#777 verifier API](https://github.com/advatar/ActiveChain/pull/783) and [#778 integration](https://github.com/advatar/ActiveChain/pull/784). My recommendation is to make **three changes before #776 is frozen**: fix the epoch-root relation, simplify the public nullifier model, and introduce a canonical receipt envelope. The subprocess choice and weak-subjectivity policy can live primarily in #777.

### 1. Public nullifiers: expose **class-neutral usage nullifiers**, not both lists

The current #776 implementation has:

```rust
nullifier =
    H(chain, project, policy, claim_class, event, claimant_secret)

usage_nullifier =
    H(chain, project, policy, event, claimant_secret)
```

and publishes **both individual arrays** plus their roots.

I would change this.

For v1, the public journal should expose individual **class-neutral `usage_nullifiers` only**, because those are the things the durable verifier actually needs to detect reuse across compatible billing classes. Do **not** expose individual class-specific nullifiers as well. At most retain:

```text
class_nullifier_root
usage_nullifier_root
usage_nullifier_count
usage_nullifiers[]
```

The class-specific list adds linkability and journal size without materially strengthening duplicate-billing detection.

There is an unavoidable privacy tradeoff here: if independent parties are expected to test whether two claims intersect without trusting a central state holder, they need either stable equality tags such as usage nullifiers **or** a stateful cryptographic accumulator with proofs. You cannot simultaneously hide all equality tags and perform arbitrary independent set intersection.

I would **not introduce a sophisticated accumulator into v1** merely to remove 48-byte pseudorandom nullifiers. It makes #776 stateful, substantially enlarges the relation and creates concurrency/root-update semantics.

The clean future v2 is:

```text
previous_usage_root
        │
        ▼
ZK non-membership + insertion
        │
        ▼
next_usage_root
```

using an authenticated set. But that should be a deliberately designed state-transition protocol, not slipped into this guest now.

**Decision for #776:** publish only the class-neutral usage-nullifier list; keep other nullifiers committed but not individually public.

---

### 2. One-claim ZK + durable historical rejection is sufficient for v1

I agree with the architecture implied by #776 → #777:

```text
RISC Zero
    proves the claim itself is internally non-overlapping
                     │
                     ▼
durable verifier registry
    rejects previously consumed usage nullifiers
```

You **do not need the #776 receipt itself to prove non-membership against historical state**.

But the semantic distinction needs to be explicit:

```text
receipt valid
≠
globally unique claim
```

Instead:

```text
receipt valid
+
all usage_nullifiers absent from durable registry
+
atomic reservation/insertion
=
verified billable claim
```

That last operation must be atomic. Two concurrent verification requests containing the same nullifier cannot both pass the read-before-write check.

So #777 should conceptually do:

```rust
BEGIN TRANSACTION

verify_receipt();
verify_anchor();

for n in claim.usage_nullifiers {
    assert_not_spent(n);
}

insert_all_atomically(claim.usage_nullifiers);

COMMIT
```

and the durable key should include the relevant compatibility/billing domain, which relates to answer 4.

The downside is important: an **offline RISC Zero verifier can prove the relation but cannot independently prove global historical uniqueness**. The API/SDK should therefore distinguish something like:

```text
relation_verified
usage_verified
anchor_verified
```

rather than presenting the RISC receipt alone as “non-double-billing proof.”

If later you need trustless offline uniqueness, then move to an accumulator/checkpoint model in `actum.non-overlap.risc0.v2`.

**So: no historical-set witness inside the v1 receipt.**

---

### 3. Do not put full signature verification inside RISC Zero — but the current epoch relation must change

This is the most important change to PR #782.

The frozen #772 contract says an activity epoch is a Merkle tree whose leaves are:

```text
H(0x00 || event_id)
```

where `event_id` is the canonical commitment to the real developer event.

But #782 currently calculates:

```rust
event_leaf =
    H(
      chain_id,
      project_id,
      policy_id,
      claim_class,
      sequence,
      start_ms,
      end_ms,
      units,
      nonce
    )
```

and then requires:

```rust
root(work_event_leaves) == public.epoch_root
```

Those are **not the same epoch tree**.

That needs fixing before the image ID is frozen.

I recommend this split:

```text
OUTSIDE GUEST
──────────────────────────
canonical SignedDeveloperEvent
ML-DSA verification
collector/project/authorization checks
canonical epoch verification
finalized epoch anchor verification

                    produces trusted
                    epoch_root + event commitments
                           │
                           ▼

INSIDE GUEST
──────────────────────────
private canonical event fields
event_id derivation
Merkle inclusion paths → exact epoch_root
metering-policy evaluation
interval non-overlap
claimed totals
usage-nullifier derivation
```

So the guest should **prove inclusion**, but it does not need to execute ML-DSA verification.

For every private event witness, give it enough canonical event information to derive the frozen #772 `event_id`, plus its Merkle authentication path:

```rust
struct WorkEventWitnessV1 {
    event: DeveloperEventV1,
    event_id: Digest384,           // optional; guest can derive
    merkle_index: u32,
    merkle_path: Vec<Digest384>,
}
```

Then:

```text
DeveloperEventV1
      ↓ canonical commitment
event_id
      ↓
H(0x00 || event_id)
      ↓ authentication path
public.epoch_root
```

This makes the work proof cryptographically about the **same epoch that Actum anchors**.

I would avoid ML-DSA inside the zkVM unless there is a strong privacy reason for hiding the complete signed event from every verifier. Verification of signatures, finalized anchors and the RISC Zero receipt can be composed by the public verifier. The frozen #772 contract already describes verification as a composition of these checks rather than saying one zkVM invocation must perform all of them.

So the answer to #3 is:

**Consume an independently authenticated epoch root, but require the guest to prove canonical event commitment + Merkle inclusion against that exact root. Do not merely trust a root while feeding unrelated metering witnesses into the guest.**

That is the main change I would make to #782.

---

### 4. Don't prohibit evidence reuse across every proof class

I would change the current conservative rule.

The frozen contract gives the three proofs different meanings:

```text
AttentionProof
    measures human attention

ComputeProof
    measures computational/model resources

ContributionProof
    establishes attribution/linkage to an artifact
```

`ContributionProof` is particularly different: it is fundamentally an **attestation/composition claim**, not inherently another meter.

If Alice spent 30 minutes working on commit X, this should be perfectly legitimate:

```text
AttentionProof:
    "30 minutes attributable human attention"

ContributionProof:
    "that human evidence contributed to commit X"
```

Making the second proof illegal because the underlying event appeared in the first would make ContributionProof much less useful.

Instead, add an explicit **usage/billing domain**:

```text
usage_domain =
    H(policy_id, billing_dimension, entitlement_scope)
```

and derive:

```text
usage_nullifier =
    H(
      chain_id,
      project_id,
      usage_domain,
      canonical_event_id,
      claimant_secret
    )
```

Then define compatibility in `MeteringPolicyV1`.

For example:

| Evidence reuse | Default |
|---|---|
| Attention → Attention billing | reject |
| Compute → Compute billing | reject |
| Attention → Compute | allowed if distinct evidence dimension |
| Attention → Contribution | allow |
| Compute → Contribution | allow |
| Contribution → Contribution | allow unless same bounty/entitlement |
| Same evidence → same payment entitlement | reject |

The invariant should therefore be:

> **An economic entitlement cannot consume the same underlying usage twice within the same mutually exclusive billing domain.**

Not:

> An event may appear in only one proof forever.

This is much more general and will survive future claim classes.

---

### 5. Definitely publish a separate canonical Actum receipt envelope

I would **not freeze `postcard::to_stdvec(&Receipt)` as the Actum external wire format**.

PR #782 currently does exactly that:

```rust
postcard::to_stdvec(&self.receipt)
```

with a 4 MiB size limit.

RISC Zero explicitly warns that `Receipt` is recursively structured and that when receiving arbitrary third-party receipt bytes, decoders should enforce recursion/depth limits; its documentation specifically notes that not all serde codecs have appropriate protections.  [oai_citation:0‡docs.rs](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/struct.Receipt.html)

There is another architectural reason: a RISC Zero `Receipt` deliberately **does not contain the trusted image ID**. The verifier supplies the expected ImageID to `Receipt::verify`. RISC Zero also warns that receipt metadata such as SDK/prover context is **not cryptographically bound and must not drive security decisions**.  [oai_citation:1‡docs.rs](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/struct.Receipt.html)

So freeze an Actum object such as:

```rust
WorkProofReceiptEnvelopeV1 {
    envelope_revision: u16,

    proof_profile: "actum.non-overlap.risc0.v1",

    proof_system: "risc0",
    proof_system_revision: ...,

    image_id: Digest256,

    journal_revision: u16,
    journal: Vec<u8>,
    journal_commitment: Digest384,

    receipt_encoding: ReceiptEncodingV1,
    receipt_bytes: Vec<u8>,

    receipt_commitment: Digest384,
}
```

Canonicalize **that** with the ActiveChain canonical codec.

The verification algorithm is then:

```text
canonical envelope decode
        ↓
check profile/revisions/image ID against verifier policy
        ↓
bounded safe receipt decode
        ↓
receipt.verify(PINNED_IMAGE_ID)
        ↓
exact receipt.journal == envelope.journal
        ↓
decode canonical Actum journal
        ↓
verify claim
```

The `image_id` inside the submitted envelope is informational/binding data; it must **never cause the verifier to choose what image to trust**. The trusted expected image ID comes from the verifier's pinned profile. That matches RISC Zero's verification model.  [oai_citation:2‡docs.rs](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/struct.Receipt.html)

You can change the inner receipt encoding in a later envelope revision without changing the Actum protocol.

So for #5: **yes, separate canonical envelope. I would consider that a freeze blocker.**

---

### 6. Use the standalone verifier subprocess

I agree with your recommendation.

For ProofOfWork/Node I would use:

```text
Node / TS
    │ bounded stdin
    ▼
actum-work-proof-verifier
    │
    ├─ canonical envelope parser
    ├─ RISC Zero verifier
    ├─ finality verifier
    └─ usage registry
    │
bounded stdout
    ▼
Node
```

rather than Rust FFI.

Advantages here are substantial:

- Rust panics/memory issues don't share Node's address space;
- RISC Zero's heavy dependency graph stays out of the Node ABI;
- Rust upgrades do not create N-API ABI coupling;
- resource limits/timeouts are straightforward;
- CLI behavior can be independently tested;
- the same verifier is usable from Node, Python, shell and server infrastructure.

I would use JSON for the **process control protocol**, but not as the object being cryptographically committed. Base64/hex or a file descriptor can transport the canonical binary envelope.

Make the subprocess contract:

```text
one request → one response
max stdin
max stdout
deadline
memory limit where available
no network required for purely local mode
fixed verifier binary revision
no ambient configuration affecting trust pins
```

FFI still makes sense for the iOS/Android offline-verifier SDK. It just shouldn't be the Node production boundary.

---

### 7. Weak subjectivity: require a signed, monotonically advancing trust bundle containing a checkpoint

Of the options you named, **trusted checkpoint + signed trust-bundle sequence** is the right primitive.

Neither of these is sufficient:

```text
maximum finality age
minimum finalized height
```

A long-range attacker can construct a recent-looking fork at a high height. Those are freshness/rollback controls, not an authenticated bootstrap point.

I'd define:

```rust
ActumTrustBundleV1 {
    sequence: u64,

    chain_id: Digest384,
    genesis_commitment: Digest384,

    checkpoint_height: u64,
    checkpoint_block: Digest384,
    checkpoint_finality_commitment: Digest384,
    validator_set_root: Digest384,

    protocol_revision: u32,
    finality_verifier_revision: u32,
    work_verifier_revision: u32,

    issued_at_ms: u64,
    supersedes: Digest384,

    signatures: ...
}
```

The verifier stores the highest accepted bundle sequence and rejects rollback.

Then a finalized work-proof anchor must either:

```text
equal checkpoint
```

or prove a finalized chain descendant of it.

I would maintain **two separate age policies**:

```text
weak_subjectivity_checkpoint_age
```

and

```text
application_anchor_freshness
```

because they're answering different questions.

The exact maximum checkpoint age shouldn't be an arbitrary constant. It should be constrained by Actum's validator-accountability lifecycle:

\[
WS_{\max}
<
\text{minimum period during which old validator authority remains slashable/accountable}
-
\text{safety margin}
\]

If Actum has not frozen that validator lifecycle yet, put the limit in the signed trust policy rather than pretending that “7 days” or “30 days” is cryptographically meaningful.

Minimum finalized height can additionally prevent local rollback, but it should be remembered state, not a replacement for a checkpoint.

---

## What I would tell Codex to change in #776 now

I would send essentially these four instructions:

1. **Replace the synthetic `ACTUM-WORK-EVENT-V1` epoch tree with the canonical #772 event tree.** Private work witnesses must derive the canonical `event_id` and prove Merkle membership under the exact anchored `ActivityEpochV1.event_root`.

2. **Publish only class-neutral usage-nullifier values.** Remove the individual class-specific nullifier vector from the journal; retain its root if useful. Historical uniqueness remains an atomic durable #777 verifier operation.

3. **Change cross-class semantics from universal event consumption to policy-defined billing domains.** ContributionProof may reuse Attention/Compute evidence unless it represents the same economic entitlement.

4. **Replace raw postcard `Receipt` transport with `WorkProofReceiptEnvelopeV1`.** The canonical envelope pins profile/image/journal/encoding revisions and treats the RISC Zero receipt as bounded opaque proof material. Do not trust RISC Zero receipt metadata for security decisions. RISC Zero itself says the ImageID must be supplied by the verifier and its receipt metadata is not cryptographically bound.  [oai_citation:3‡docs.rs](https://docs.rs/risc0-zkvm/latest/risc0_zkvm/struct.Receipt.html)

I would **not block #776** on historical accumulator proofs, ML-DSA-inside-zkVM, the subprocess implementation, or the final weak-subjectivity machinery. Those belong cleanly in #777/#775. But **the epoch-root mismatch and the external receipt format should be fixed before the #776 image ID and vectors are treated as frozen**, because both change the actual statement being proven. 
