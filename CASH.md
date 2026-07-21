# Yes—but cash must be a first-class execution path

The developer’s answer is correct: there is no defensible TPS figure yet. A three-validator convergence rehearsal proves consensus behavior, not throughput.

The architecture can nevertheless be designed to process cash payments far more efficiently than general smart-contract transactions. The decisive change is:

> **Do not send every payment through the general ObjectVM, globally order every independent transfer, permanently replicate every post-quantum signature, and charge each payment a share of the entire security budget.**

ActiveChain should implement a dedicated **Cash Plane** with fixed semantics, parallel settlement, specialized proofs, a separate fee market, and native payment channels.

The performance thesis is:

1. Cash transfers use a native transition, not arbitrary contract execution.
2. Independent coin spends do not require a single total order.
3. Consensus certifies batch roots rather than individual transactions.
4. PQ signatures are authorization witnesses, not permanent historical state.
5. Validators verify compact batch proofs rather than repeating all work.
6. Issuance funds baseline security; user fees fund marginal resource consumption.
7. High-frequency micropayments settle through native channels or payment batches.

---

# 1. Introduce `CashTransferV1`

A normal public payment should not invoke the general contract VM.

It should use a fixed protocol action:

```text
CashTransferV1 {
    input_cells[]
    recipient
    amount

    payment_session_key_id
    fee_reserve
    maximum_fee_price
    valid_until

    authorization_witness_commitment
}
```

For the native coin, the transaction does not need to repeat:

- the asset identifier;
- chain identifier;
- fee schedule;
- sender public key;
- full controller policy;
- contract bytecode;
- arbitrary call data.

Those values are implicit in the transaction version, batch header, or referenced session object.

For the common one-input payment, outputs are also partly implicit:

```text
recipient_output = amount
sender_change    = input_amount - amount - actual_fee
```

A simple cash transaction therefore performs only:

1. input-cell membership verification;
2. one authorization check;
3. double-spend prevention;
4. value conservation;
5. fee calculation;
6. creation of recipient and change cells.

There are no arbitrary loops, dynamic state discovery, callbacks, or contract reentrancy.

## Fixed and predictable charging

`CashTransferV1` receives a fixed resource schedule:

```text
base_cash_units
+ bytes_in_canonical_intent
+ number_of_inputs
+ number_of_outputs
+ authorization_witness_class
```

The wallet can calculate the maximum charge before the user signs. Cash payments should not produce “estimated gas” surprises.

A token other than the native coin can use this lane only if it adopts an immutable `CashAssetProfile` with bounded transfer policy. Tokens with arbitrary callbacks or mutable execution logic remain in the contract lane.

---

# 2. Give cash its own capacity and fee market

AI jobs, large blobs, private contract execution, and ordinary payments must not bid for one undifferentiated resource.

Use separate block lanes:

```text
Block capacity
├── Cash lane
├── Shielded-cash lane
├── General-contract lane
├── Data/blob lane
└── Compute-job settlement lane
```

The cash lane has:

- its own target utilization;
- its own base fee;
- its own hard maximum;
- reserved minimum capacity;
- a bounded transaction format;
- age-based inclusion;
- no fine-grained priority auction.

I would initially reserve **30–50% of transaction-intent capacity** for ordinary payments. Unused cash capacity can be borrowed by other lanes late in the slot, but other workloads cannot consume the reservation before that point.

This prevents a popular AI application or blob auction from pricing ordinary payments out of the network.

## Overload behavior

No protocol can guarantee unlimited throughput, permanent decentralization, instant finality, and perpetually negligible fees simultaneously.

When the cash lane is overloaded, users should be able to choose:

- normal fee and longer queue time;
- a coarse expedited class;
- a native payment channel;
- a merchant-sponsored batch.

The default behavior should be **increased latency before extreme fee escalation**. Cash users should not be forced into an uncontrolled priority auction.

---

# 3. Add an owned-coin fast path

A payment consuming only owned Coin Cells has a useful property:

> The only possible state conflict is another transaction attempting to spend the same input cell.

It does not need to be globally ordered against every unrelated payment.

## Fast-path flow

```text
Wallet creates CashTransferV1
            ↓
Cash DA workers disseminate the intent
            ↓
Batcher groups non-conflicting transfers
            ↓
Cash prover generates a batch proof
            ↓
Validators verify proof and lock input cells
            ↓
More than two-thirds certify the batch
            ↓
Payment becomes final
            ↓
Batch certificate is checkpointed into global state
```

Validators maintain a persistent lock for each input cell. They do not sign two competing spends of the same input.

Two certificates each containing more than two-thirds of stake must intersect in more than one-third of stake. Under the assumption that less than one-third is Byzantine, at least one honest validator lies in that intersection and refuses to certify both conflicting spends.

Therefore two conflicting cash certificates cannot both form.

## Conflict fallback

If competing spends split votes before either obtains a certificate, the transactions fall back to the ordinary globally ordered lane.

The fast path is used only for:

- owned public Coin Cells;
- fixed-profile fungible assets;
- bounded fee handling;
- no shared contract state;
- no dynamic application callbacks.

A purchase involving escrow, an exchange, a shared liquidity pool, or an organizational approval object uses the general ordered path.

## One validator set, not weaker shards

Cash batches may be partitioned for execution and proving, but they remain under:

- the same validator set;
- the same stake threshold;
- the same state root;
- the same finality domain.

These are physical execution partitions, not independently secured chains.

---

# 4. Keep the entire path post-quantum

There is no need for P-256, secp256k1, Ed25519, or BLS.

A wallet should derive role-specific PQ keys from one high-entropy master seed:

```text
Master seed
   │
   ├── ML-DSA-65 root-control key
   ├── ML-DSA-65 credential and organization keys
   ├── ML-DSA-44 short-lived payment-session keys
   ├── ML-KEM-768 private-payment receiving keys
   └── SLH-DSA long-term recovery key
```

A domain-separated derivation could conceptually use:

\[
s_i =
\operatorname{KMAC256}
(
s_{\text{master}},
\text{chain}\parallel\text{role}\parallel\text{account}\parallel i
)
\]

Each derived seed deterministically produces the corresponding key pair.

The root principal registers a payment-session key once:

```text
PaymentSession {
    principal
    session_public_key
    maximum_total_spend
    maximum_payment
    allowed_assets
    valid_until
    sequence_range
}
```

Individual payments then carry only a compact `payment_session_key_id`, not the complete public key or root authorization policy.

FIPS 204 fixes an ML-DSA-44 public key at 1,312 bytes and a signature at 2,420 bytes; ML-DSA-65 uses a 1,952-byte public key and a 3,309-byte signature. Those sizes make repeating public keys and permanently replicating every signature prohibitively wasteful at cash-scale throughput.  [oai_citation:0‡nvlpubs.nist.gov](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf)

Keys may be deterministically recoverable, but transaction signing should use the hedged signing mode by default. FIPS 204 permits deterministic signing while explaining that fresh signing randomness also supports resistance to side-channel and fault attacks.  [oai_citation:1‡nvlpubs.nist.gov](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf)

---

# 5. Separate transaction intent from authorization witness

This is the most important PQ bandwidth optimization.

A transaction has two kinds of data.

## Canonical intent data

Needed to reconstruct ledger state:

```text
input cell references
recipient
amount
fee limits
expiry
session-key identifier
authorization-witness commitment
```

This data enters the normal DA layer and remains available through the protocol retention and snapshot process.

## Authorization witness data

Needed to prove that the transition was authorized:

```text
ML-DSA signature
credential presentation
capability paths
policy witnesses
Merkle membership paths
```

This data is distributed to permissionless batchers and provers, committed by hash, and retained through the proof and audit window. It does not need to become permanent transaction history after the validity proof has finalized.

The final proof establishes that the witness matching the public commitment authorized the exact canonical intent.

## Why this is essential

Suppose the compact canonical payment intent is 180 bytes.

At a **design target** of 20,000 payments per second:

```text
canonical intent data:  3.6 MB/s
per 3-second slot:     10.8 MB
```

If every ML-DSA-44 signature were also permanently replicated:

```text
signature data alone: 48.4 MB/s
```

before networking, erasure coding, storage, or protocol overhead.

That does not mean signatures disappear. It means:

- they go to short-lived witness distribution;
- they are verified inside the cash proof;
- independent archives may retain them;
- validators do not all store them forever;
- state recovery depends on the payment intents and proof, not old signatures.

This design dramatically reduces long-term storage and ordinary-validator bandwidth.

---

# 6. Build a specialized `CashAIR`

General ObjectVM proving is unnecessary for ordinary payments.

Implement a dedicated transparent STARK statement:

```text
CashBatchProof proves that:

1. every input cell existed in the pre-state;
2. every authorization witness matched its commitment;
3. every ML-DSA signature was valid;
4. every payment session was active and within its limits;
5. no input cell appeared twice;
6. each input was consumed exactly once;
7. total input value equaled outputs plus fees;
8. every output was correctly formed;
9. all fees were calculated under the finalized fee schedule;
10. the claimed partition roots and global root were updated correctly.
```

The proof system should have specialized tables for:

- SHAKE;
- ML-DSA polynomial and NTT operations;
- Merkle multiproofs;
- cell consumption;
- amount arithmetic;
- fee arithmetic;
- session-budget updates.

This is much cheaper than proving the same operation by emulating a general CPU instruction by instruction.

## Recursive partitioning

```text
Individual payment traces
            ↓
Cash microbatch proofs
            ↓
State-partition proofs
            ↓
One recursive cash-slot proof
            ↓
Global transition proof
```

Multiple permissionless provers can produce different microbatches concurrently.

During the initial hardening period, validators should both:

- directly revalidate the fixed cash kernel; and
- verify the batch proof.

Once long-running comparison shows no disagreement, the proof can become the primary validation path.

Deterministic parallel execution under a preset result order has already been demonstrated as a viable execution strategy by Block-STM; its benchmark figures are not directly transferable to ActiveChain, but its deterministic conflict-detection model supports this architectural direction.  [oai_citation:2‡arXiv](https://arxiv.org/pdf/2203.06871)

---

# 7. Consensus must order roots, not payment payloads

The block proposer must not individually distribute tens of thousands of payments.

Use multiple cash DA workers:

```text
Cash producer 1 ─┐
Cash producer 2 ─┤
Cash producer 3 ─┼── availability-certified cash batches
...             ─┤
Cash producer N ─┘
                         ↓
Consensus orders compact batch certificates
```

The consensus proposal carries:

- batch roots;
- availability certificates;
- cash proofs;
- input-lock commitments;
- aggregate resource use.

Bulk payment data travels over the DA network.

Separating reliable transaction dissemination from ordering is the core idea behind Narwhal-style architectures: it removes the consensus leader’s network link as the only route through which transaction data must pass.  [oai_citation:3‡arXiv](https://arxiv.org/abs/2105.11827)

## PQ consensus traffic remains nearly constant

A block containing 1,000 payments and a block containing 50,000 payments should have nearly the same consensus-control payload:

```text
parent
round
cash batch roots
proof roots
DA certificates
fee totals
validator vote
```

ML-DSA validator votes are still relatively large, so vote propagation must use aggregation trees and compact signer sets. But this cost is paid per batch or round—not per cash payment.

---

# 8. Partition state for parallel updates

Partition the Coin Cell tree by coin identifier prefix:

```text
Cash state
├── Partition 000
├── Partition 001
├── ...
└── Partition 4095
```

Each cash batch supplies compact multiproofs for the partitions it touches.

Independent partitions can:

- verify input membership concurrently;
- calculate spent sets concurrently;
- create output cells concurrently;
- produce subproofs concurrently;
- update partition roots concurrently.

The global proof then combines the changed partition roots atomically.

A payment that creates an output in another partition remains one atomic state transition. It is not an asynchronous bridge between shards.

---

# 9. Make payment history expirable

High TPS is impossible if every validator must preserve every retail transaction forever.

For cash:

- spent Coin Cells are removed from active state;
- current unspent cells remain;
- state snapshots capture the current ownership state;
- old transaction intents expire after the defined history window;
- old authorization witnesses expire much sooner;
- receipt and archival providers preserve history for users who need it;
- wallets retain their own signed transaction history.

A new node reconstructs current state from:

```text
latest certified snapshot
+ state deltas since the snapshot
```

It does not replay decades of coffee purchases.

## Refundable cell deposits

Creating a Coin Cell should lock a small storage deposit:

\[
D =
\text{cell bytes}
\times
\text{state price}
\times
\text{target lifetime}
\]

When the cell is spent, the deposit returns to the spender or is rolled into the outputs.

This prevents UTXO spam without turning the storage charge into a permanently lost fee.

Very small payments below the viable cell-deposit threshold should use channels or batched settlement rather than creating microscopic perpetual outputs.

---

# 10. Fund security separately from marginal transaction cost

Low cash fees are difficult if every payment must single-handedly fund the entire validator security budget.

The economic split should be:

```text
Bounded issuance
    → minimum validator and consensus security budget

Transaction fees
    → marginal DA, proof, state, and ordering costs

Congestion rents
    → burn or security reserve
```

The cash fee becomes:

\[
F_{\text{cash}}
=
p_{\text{DA}}B
+
p_{\text{witness}}W
+
p_{\text{state}}\Delta S
+
\frac{C_{\text{proof}}}{N_{\text{batch}}}
+
\frac{C_{\text{consensus}}}{N_{\text{batch}}}
\]

where:

- \(B\) is canonical intent bytes;
- \(W\) is short-lived witness load;
- \(\Delta S\) is net active-state growth;
- \(N_{\text{batch}}\) is payments amortizing shared proof and consensus work.

As batch size grows, consensus and recursive-proof cost per payment decreases.

This is how fees become small without pretending validators, DA providers, and provers work for free.

## No fiat guarantee at the protocol level

A blockchain cannot guarantee a fixed cent-denominated fee without introducing a fiat price mechanism.

Instead:

- the protocol guarantees a small fixed resource footprint;
- competitive providers price those resources in the native coin;
- paymasters can quote a fixed fee in a stablecoin or payment asset;
- merchants can sponsor fees;
- wallets display a final all-inclusive quote before signing.

A user paying with a stablecoin should be able to reimburse a paymaster in that stablecoin while the paymaster supplies native coin to consensus.

---

# 11. Native merchant and micropayment channels

Even a highly scalable base layer should not globally settle every millisecond-level interaction.

Implement native channels:

```text
PaymentChannel {
    funding_cells
    participants
    payment_asset
    maximum_expiry
    latest_state_commitment
    settlement_policy
}
```

The channel opens with a PQ-authorized on-chain transaction.

Inside the channel, participants exchange:

- ML-DSA-signed balance states;
- hash-chain payment vouchers;
- or batched payment commitments.

These messages are immediate and do not consume global block space.

Only channel opening, dispute, and final settlement reach the global chain.

This supports:

- transit payments;
- streaming AI usage;
- content micropayments;
- merchant tabs;
- machine-to-machine payments;
- repeated subscriptions.

Channels remain noncustodial. A hub may route liquidity, but it cannot spend user funds outside the signed channel state.

Channel messages must not be counted as base-layer TPS in public benchmarks. Report them separately as user-level payment throughput.

---

# 12. Private cash needs its own fixed proof profile

Private transactions should not go through arbitrary private-contract proving.

Define `ShieldedCashV1`:

```text
ShieldedCashV1 {
    input_nullifiers[]
    output_commitments[]
    encrypted_output_notes[]
    fee_authorization
    shielded_cash_proof
}
```

The fixed proof establishes:

- note membership;
- private authorization;
- non-reuse of nullifiers;
- value conservation;
- output correctness;
- fee correctness.

Private-payment proofs are recursively aggregated before validators see them.

The shielded lane should have:

- independent capacity;
- independent proof pricing;
- fixed two-input/two-output and larger batch profiles;
- common fee sponsorship to reduce sender linkage;
- padded transaction classes.

Its initial measured TPS will almost certainly be below public cash TPS because proving and ciphertext costs are higher. That is acceptable as long as the distinction is explicit.

---

# 13. A defensible performance target

I would define the following as **engineering gates**, not public claims.

| Stage | Public cash target | Shielded cash target | Conditions |
|---|---:|---:|---|
| Semantic devnet | 1,000 sustained TPS | 100 TPS | Real Coin Cells and real ML-DSA |
| Performance devnet | 5,000 sustained TPS | 500 TPS | Real DA coding and state updates |
| Incentivized testnet gate | 10,000 sustained TPS | 1,000 TPS | Geographic validators and real proofs |
| Scale testnet | 20,000 sustained TPS | 2,500–5,000 TPS | Parallel DA workers and recursive proofs |
| Long-term target | 50,000+ public TPS | Benchmark-dependent | No validator-hardware regression |

For the incentivized-testnet gate, require:

- at least one hour at sustained target load;
- no continuously growing queue;
- real ML-DSA signatures;
- real fee reservations and native-coin settlement;
- real Reed–Solomon coding;
- real state-tree updates;
- real cash proofs;
- p95 order or cash-certificate finality within the target;
- p95 proof-backed state finality within the target;
- validator CPU, memory, disk, and network within published limits;
- no disabled signature checks;
- no fake receipts;
- no in-memory-only state shortcut.

The 10,000 TPS value is a launch gate I would choose, not a statement about the present implementation.

---

# 14. Build a benchmark that measures the correct thing

A TPS report must define exactly what one transaction means.

## Workload profiles

Use at least:

| Profile | Transaction |
|---|---|
| `cash-1x2` | One input, recipient output, implicit change |
| `cash-2x2` | Two inputs, two explicit outputs |
| `cash-batch-16` | One authorization, sixteen recipients |
| `cash-merchant-hotspot` | Many payments to one merchant |
| `cash-cross-partition` | Inputs and outputs across state partitions |
| `shielded-2x2` | Two private inputs and two private outputs |
| `policy-payment` | Session capability and spending limit |
| `invalid-replay` | Reused input, expired fee ticket, bad signature |
| `mixed-production` | Cash, contracts, DA, private transfers, and jobs |

## Node configurations

Test:

```text
4 validators
16 validators
64 validators
256 validators
1,024 validators when network benchmarks justify it
```

Use both:

- local saturation testing;
- geographically distributed WAN testing;
- latency and packet-loss emulation;
- validator failures;
- prover failures;
- DA-worker loss.

## Required metrics

Publish:

```text
submitted TPS
mempool-admitted TPS
DA-certified TPS
ordered TPS
proof-produced TPS
proof-finalized TPS

p50 / p95 / p99 latency
ML-DSA verifications per second
bytes per transaction
canonical bytes versus witness bytes
DA ingress and egress
validator CPU and memory
state-update throughput
proof generation latency
proof verification latency
queue depth
fee per workload at each utilization level
```

The headline number should be:

> **Sustained proof-finalized cash transfers per second under the declared validator, network, DA, and hardware configuration.**

Not submitted requests. Not transactions accepted by an RPC endpoint. Not payment-channel updates. Not a one-second burst.

---

# 15. Diagnose the bottleneck rather than guessing

The benchmark should map each failure mode to an engineering response.

| Bottleneck | Required response |
|---|---|
| ML-DSA verification CPU | SIMD implementation, key caching, parallel verification, batch authorization |
| ML-DSA bandwidth | Key references, witness separation, payment batching, channels |
| Proposer bandwidth | Multi-producer DA and certificate-only consensus |
| State-tree writes | Partitioned trees, sorted multiproofs, batched database writes |
| Transaction conflicts | Explicit Coin Cells and owned-cell fast path |
| Proof latency | Specialized CashAIR, smaller microbatches, more recursive provers |
| Validator bandwidth | DA sampling instead of full payload download |
| Historical storage | Snapshots, history expiry, short witness retention |
| Fee volatility | Cash-specific base fee, reserved capacity, stablecoin paymasters |
| Merchant latency | Cash certificates and payment channels |
| UTXO fragmentation | Wallet consolidation and batched merchant sweeps |

---

# 16. Concrete implementation tranche

Based on the developer status you pasted, this should now become the highest-priority implementation tranche.

## Tranche A — real native money

Implement:

```text
NativeAssetDefinition
CoinCell
CoinCellSetRoot
CoinTransfer
CoinMintTransition
CoinBurnTransition
SupplyRoot
```

Prove:

- no double spend;
- value conservation;
- mint only through protocol issuance;
- burn accounting;
- fee reserve ownership.

## Tranche B — cash kernel

Implement:

```text
CashTransferV1
CashTransferBatchV1
implicit change outputs
fixed resource schedule
payment session keys
cash-specific receipts
```

Do not call ObjectVM for this action.

## Tranche C — PQ wallet sessions

Implement:

```text
deterministic master-seed derivation
ML-DSA-65 root control
ML-DSA-44 payment sessions
ML-KEM-768 private receiving keys
SLH-DSA recovery
key registration and compact key IDs
hedged signing
```

No P-256 compatibility path should enter native transaction validation.

## Tranche D — cash DA and witness separation

Implement:

```text
canonical intent batches
short-lived authorization-witness batches
witness commitments
intent compression
batch dictionaries
finite retention
archive hooks
```

## Tranche E — parallel cash state

Implement:

```text
partitioned Coin Cell tree
input-lock table
parallel membership verification
parallel output creation
cash fast-path certificates
ordered conflict fallback
```

## Tranche F — `CashAIR`

Implement proofs for:

```text
ML-DSA verification
cell membership
double-spend exclusion
value conservation
fee settlement
session-budget enforcement
partition-root updates
recursive batch aggregation
```

## Tranche G — cash fee market

Implement:

```text
cash base fee
cash capacity reservation
marginal provider payments
refundable state deposits
stablecoin paymaster interface
merchant fee sponsorship
```

## Tranche H — benchmark harness

Implement one command such as:

```bash
activechain-bench cash \
  --validators 64 \
  --workers-per-validator 4 \
  --target-tps 10000 \
  --duration 3600 \
  --workload mixed-cash-v1 \
  --real-pq \
  --real-da \
  --real-proof \
  --network-profile wan-4-region \
  --report out/cash-10k.json
```

The command should produce raw machine-readable results, charts, environment manifests, binary hashes, and reproducibility instructions.

---

# What should be claimed now

The correct current statement is:

> **ActiveChain has validated small-testnet consensus behavior. Its cash throughput has not yet been measured. The architecture is being extended with a native PQ cash lane designed to separate payment intent from authorization witnesses, parallelize independent Coin Cell transfers, batch proof generation, and isolate payment fees from general compute congestion.**

After the benchmark gate is passed, the statement can become:

> **ActiveChain sustains X proof-finalized public cash transfers per second and Y shielded transfers per second under the published validator, network, proof, DA, and hardware configuration.**

The route to being substantially faster is not a larger generic block. It is a specialized cash kernel, owned-cell parallelism, certificate-only consensus, short-lived PQ witnesses, horizontal DA, recursive cash proofs, bounded history, and native channels—while keeping the security path post-quantum from the first transaction.
