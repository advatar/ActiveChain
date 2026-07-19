# Core principle

We should **not** pay everyone who claims to have verified a block or proof.

Verification is usually private and difficult to observe. An operator could run thousands of identities, copy another node’s answer, sign without checking, or claim to have performed work that cannot be distinguished from passive observation. This is the classic **verifier’s dilemma**: when errors are rare, rational participants may try to collect rewards without doing the costly checking. Work on Truebit and later verifier-incentive mechanisms explores random assignments, challenge games, multiple selected verifiers, and proofs of independent execution for precisely this reason.  [oai_citation:0‡people.cs.uchicago.edu](https://people.cs.uchicago.edu/~teutsch/papers/truebit.pdf?utm_source=chatgpt.com)

The right rule is:

> **Pay verifiers for accountable, assigned, externally checkable services—not for asserting that they ran a node.**

Verification incentives should purchase four things:

1. **Attention:** someone was economically responsible for checking a particular result.
2. **Availability:** someone retained and served the data needed to verify.
3. **Diversity:** independent implementations and operators checked the same protocol.
4. **Accountability:** incorrect attestations expose a bond to penalties.

---

# Five verifier roles

We should not create one generic “verifier” class. The system needs several economically distinct roles.

| Role | What it verifies | Main compensation |
|---|---|---|
| Finality verifier | Consensus, DA certificate, transition proof, inclusion rules | Protocol security reward |
| DA verifier and custodian | Sampling, reconstruction and retained data | DA fees and custody payments |
| Audit verifier | Independent re-execution and alternative proof verification | Random-assignment stipend and bounties |
| Assurance verifier | AI jobs, bridges, attestations and application claims | User or application escrow |
| Public-goods verifier | Clients, formal models, fuzzing and monitoring | Protocol public-goods budget |

Ordinary users may run an unpaid light or full verifier for their own protection. They can opt into one of the paid service roles, but simply downloading headers should not generate protocol tokens.

---

# 1. Bonded finality verifiers

These are the active validator seats participating in BFT consensus.

Their mandatory duties are:

- verify the post-quantum quorum certificate;
- verify the data-availability certificate;
- verify the recursive transition proof;
- check canonical ordering and forced-inclusion rules;
- check protocol-version and epoch-transition rules;
- vote on the resulting block.

Ethereum provides the basic precedent: assigned validators are rewarded for timely, correct attestations and lose rewards or incur penalties when they fail their duties. The crucial difference in our design is that validators verify a succinct transition proof instead of necessarily re-executing the entire state transition.  [oai_citation:1‡ethereum.org](https://ethereum.org/developers/docs/consensus-mechanisms/pos/rewards-and-penalties/?utm_source=chatgpt.com)

## Reward design

Finality verifiers should receive approximately equal payment for equal fulfilled duties:

\[
R_v =
R_{\text{seat}}
\cdot
A_v
\cdot
T_v
+
R_{\text{special duties}}
-
P_v
\]

where:

- \(A_v\) is the fraction of assigned duties completed correctly;
- \(T_v\) is a bounded timeliness factor;
- \(P_v\) includes inactivity or objective-fault penalties.

The reward should **not** increase merely because a validator attracts excess delegated stake. Stake determines whether a seat is sufficiently backed; fulfilled work determines the seat’s reward.

This reduces the advantage of already-large staking operators.

## Penalties

| Behavior | Consequence |
|---|---|
| Missed vote | Lost reward |
| Repeated downtime | Lost reward and gradual inactivity penalty |
| Conflicting votes | Severe slash |
| Signing a proof that fails the frozen canonical verifier | Severe slash |
| False signed DA attestation | Slash |
| Invalid signed decryption or randomness share | Slash |
| Protocol-wide implementation defect | Safety halt and exceptional remediation, not indiscriminate automatic mass slashing |

The last distinction matters. A single verifier that lazily signs an objectively invalid block should bear consequences. A widely deployed bug in an officially conforming client is a systemic failure requiring a different response.

---

# 2. Paid data-availability verifiers

Data availability is a directly measurable service and therefore much easier to reward than passive proof checking.

A DA verifier can be paid for:

- retrieving randomly assigned shares before voting;
- retaining assigned shares for the hot-data period;
- responding to reconstruction requests;
- serving historical witnesses;
- reconstructing missing rows or columns;
- participating in periodic retrievability challenges.

Data-availability sampling allows small nodes to gain confidence that data was published without downloading every byte. More participating sampling nodes improve the system’s security and potential throughput.  [oai_citation:2‡Celestia Documentation](https://docs.celestia.org/learn/celestia-101/data-availability-faq/?utm_source=chatgpt.com)

## DA assignment

After a batch commitment is published, the protocol derives unpredictable assignments:

```text
DAAssignment {
    verifier
    batch_root
    sample_coordinates[]
    custody_region
    retrieval_deadline
    retention_expiry
    reward
}
```

A verifier returns:

```text
DAReceipt {
    assignment_id
    retrieved_share_hashes
    Merkle_paths
    retrieval_latency
    custody_commitment
    verifier_signature
}
```

The validator receives:

- an immediate sampling reward;
- a continuing retention payment;
- user-paid retrieval fees when it serves data;
- a reconstruction bonus when recovering unavailable shares.

## Proof of continued custody

Periodic random challenges should require the custodian to reveal committed portions of its assigned data.

Filecoin provides an established example of rewarding storage providers for successfully answering unpredictable Proof-of-Spacetime challenges and penalizing failures to demonstrate continued storage. We should use a PQ-compatible, hash-based custody mechanism rather than copy Filecoin’s complete cryptographic stack.  [oai_citation:3‡docs.filecoin.io](https://docs.filecoin.io/provide-storage/filecoin-economics/storage-proving?utm_source=chatgpt.com)

A custodian that misses one challenge due to a network fault should lose that period’s reward. Repeated or provably false custody claims can consume its service bond.

## Payment source

DA verifier rewards should be paid primarily from **DA fees**, not unrestricted inflation:

\[
\text{DA fee}
=
\text{publication}
+
\text{sampling}
+
\text{hot retention}
+
\text{reconstruction reserve}
\]

The user placing data obligations on the network funds the corresponding service.

---

# 3. Independent audit verifiers

This is the most important additional role.

An audit verifier does **not** vote on finality. It independently checks the system as a defense against:

- proof-system implementation defects;
- mismatches between VM semantics and STARK constraints;
- compiler errors;
- state-tree bugs;
- incorrect fee accounting;
- correlated validator-client failures;
- malicious or compromised prover implementations.

Audit verifiers should be selected randomly and paid even when everything is correct. Otherwise, an honest network produces no errors and therefore no economic reason to keep auditing.

## Random audit assignments

After the proof and order-set commitments are fixed, the beacon selects audit tasks:

```text
AuditAssignment {
    verifier
    block_root
    audit_type
    component_range
    implementation_requirement
    commitment_deadline
    reveal_deadline
    base_reward
}
```

Possible audit types include:

- re-execute selected transactions;
- re-execute one conflict component;
- independently calculate one state partition root;
- verify authorization and capability attenuation;
- recompute fee and rent accounting;
- verify the STARK using an independent verifier implementation;
- reproduce one AI computation segment;
- validate one credential-status transition.

Assignments must be unpredictable until after the proposer and prover have committed their results.

## Proof of audit work

The verifier re-executes the assigned component and constructs a salted execution-transcript tree:

\[
L_i =
H(
s_v
\parallel
i
\parallel
\text{instruction state}_i
\parallel
\text{object roots}_i
)
\]

It first commits:

\[
C_v = H(\text{result}\parallel\text{transcript root}\parallel n_v)
\]

After all commitments are closed, new randomness selects transcript positions. The verifier reveals Merkle paths and local execution states for those positions.

This does not prove metaphysically that the operator performed the work itself. Outsourcing cannot be completely prevented. It does make copying a final state root without constructing the committed trace economically risky.

## Payment

Selected auditors receive:

- a fixed base payment for a correct, timely audit;
- a modest availability bonus for maintaining an independent implementation;
- a large mismatch bounty if they produce objective evidence;
- no extra payment simply for being the fastest.

A suitable reward equation is:

\[
R_{v,d}
=
r_d
\cdot
\mathbf{1}[\text{correct}]
\cdot
g(\text{response time})
+
b_d
-
p_d
\]

The timeliness factor \(g\) should be capped. Otherwise, data-center proximity becomes more valuable than independent correctness.

## Coverage target

At proof-primary maturity, I would target distributed independent re-execution equal to approximately **10–25% of one full block per block**, spread across many audit verifiers.

For example:

- 32 audit assignments per block;
- each re-executes a small random component;
- overlapping assignments on the highest-risk components;
- all components eventually audited across a rolling window;
- targeted assignments increase after an upgrade.

The validity proof remains the primary correctness mechanism. Audits are defense in depth.

---

# 4. Challenge and bounty incentives

Outside challengers should always be permitted to submit objective evidence even when they were not selected for an audit.

Potential challenges include:

- invalid quorum certificate;
- invalid transition-proof acceptance;
- incorrect state root;
- invalid capability delegation;
- false DA attestation;
- duplicate nullifier;
- incorrect fee calculation;
- fraudulent compute receipt;
- bridge or attestation evidence violating its declared verification policy.

## Do not use a pure first-winner bounty

A first-to-report system encourages:

- transaction front-running;
- centralized low-latency infrastructure;
- copying another verifier’s pending challenge;
- excessive duplication;
- self-challenges by the offending party.

Instead use a commit–reveal challenge window:

1. Challengers commit to the evidence hash.
2. The commitment period closes.
3. Challengers reveal their evidence.
4. Valid precommitted challengers share the reward.
5. Earlier commitments may receive a bounded premium.
6. Invalid or frivolous challenges lose a small bond.

Truebit-related work illustrates both the importance and the complexity of preventing verifiers from free-riding or copying another challenger’s work. Multi-verifier and proof-of-independent-execution approaches are preferable to a pure single-winner race.  [oai_citation:4‡arXiv](https://arxiv.org/abs/1806.11476?utm_source=chatgpt.com)

## Bounty source

A successful bounty can be funded from:

\[
\text{bounty}
=
\alpha\cdot\text{offender slash}
+
\text{security reserve contribution}
\]

A reasonable initial policy might send:

- 40% of an objective service slash to valid challengers;
- 40% to the protocol security reserve;
- 20% to burn.

Catastrophic protocol bugs need a separate bug-bounty budget because there may be no directly slashable offender.

---

# 5. Application assurance verifiers

Applications should be able to purchase more assurance than base consensus provides.

This is especially important for:

- large AI jobs;
- external bridges;
- hardware attestations;
- real-world credentials;
- institutional actions;
- high-value private transactions;
- optimistic computation;
- external tool receipts.

The application specifies a `VerificationPolicy`:

```text
VerificationPolicy {
    evidence_types
    required_verifier_count
    accepted_implementations
    accepted_operator_policy
    maximum_concentration
    minimum_bond
    challenge_window
    coverage_requirement
}
```

The job escrow then pays selected verifiers.

## Example assurance policy

```text
Require:
    one exact PQ-STARK proof
    and three independent receipt verifiers
    and two different verifier implementations
    and no operator controlling more than one accepted signature
    and a 24-hour challenge window
```

This is a market service, not a universal consensus expense.

## Verification warranty

A verifier can also sell a bonded warranty:

```text
VerificationWarranty {
    target_root
    policy_hash
    verifier
    coverage_amount
    bond_locked
    expiry
    objective_claim_conditions
}
```

The user pays a premium. The verifier locks a bond and signs that the target satisfies the declared policy.

If objective contradictory evidence later appears, the bond pays the covered users.

This creates an incentive to perform high-quality verification even where base consensus needs only one deterministic proof check.

Warranty coverage must be limited to objectively testable statements. It cannot insure claims such as “the AI answer was wise” or “the medical opinion was good.”

---

# 6. AI verifier incentives

The AI compute plane needs several distinct verification markets.

## Exact computation

For an exact PQ-STARK job:

- the prover receives the main computation fee;
- the canonical verifier receives a small settlement fee;
- selected audit verifiers may reproduce random TensorIR components;
- outside challengers can report a malformed or incorrectly classified receipt.

Because deterministic proof verification is inexpensive, most payment should go to proof generation and independent audit—not to thousands of nodes repeating the same proof check.

## Replicated execution

A job may require \(k\) independently selected workers to run the same model or computation.

Workers:

1. commit to their outputs before seeing the others;
2. reveal after the commitment window;
3. receive payment if they match the policy’s agreement rule;
4. lose part of their bond for provably fabricated receipts.

The payment should be fixed per selected worker, not winner-takes-all.

## Optimistic jobs

For an optimistic computation:

- the worker posts a result bond;
- randomly selected verifiers receive base pay to inspect it;
- outside challengers remain eligible;
- the job settles after the challenge period;
- a successful challenge receives part of the worker’s bond.

The audit fee must be paid even when no fraud occurs.

## Hardware attestation

Attestation-chain verifiers are paid to check:

- platform certificate chain;
- measurement;
- minimum security version;
- revocation status;
- job and input commitment;
- receipt signature.

They can be slashed for objectively false validation, but not because the underlying hardware vendor later suffers an unknown vulnerability.

## Subjective evaluators

Evaluators judging quality, safety, relevance, legality, or factual accuracy should receive:

- job-specific fees;
- transparent performance history;
- appeal and disagreement records;
- reputation credentials.

They should not be automatically slashed merely because another evaluator disagrees. Subjective judgment is not cryptographic validity.

---

# 7. Public-goods verification

Some of the most important verification work does not generate a natural per-transaction receipt:

- maintaining independent clients;
- formalizing the protocol;
- proving theorems;
- developing fuzzers;
- reproducing builds;
- reviewing cryptography;
- operating public monitoring;
- maintaining test vectors;
- conducting adversarial testnets;
- checking proof-system equivalence.

These activities need a dedicated public-goods budget rather than contrived per-block token rewards.

## Funding model

I would reserve approximately **5% of the protocol security budget** for:

- independent client milestones;
- formal verification;
- security reviews;
- public test infrastructure;
- long-running differential nodes;
- reproducible-build services;
- vulnerability rewards.

Payments should be milestone-based and retroactive where possible:

```text
Milestone:
    independent client verifies 1,000,000 canonical vectors
    and follows testnet for 90 days
    and produces no unexplained state divergence
Payment:
    released in staged tranches
```

This is more defensible than paying a validator extra merely because it claims to run a minority client.

---

# 8. Ordinary verifiers should receive utility, not inflation

A normal light or full verifier should not require a token subsidy.

Its direct benefits are:

- verifying its own assets and transactions;
- avoiding dependence on a hosted RPC provider;
- better privacy;
- independent censorship detection;
- local policy and credential validation;
- faster access to relevant state;
- the ability to become an audit, DA, relay or assurance provider.

Paying every ordinary verifier from protocol issuance would be immediately Sybilable. One operator could create arbitrary verifier identities and collect arbitrary rewards.

Instead, an ordinary verifier can earn when it performs an externally consumed service:

- serving a state proof;
- serving a DA share;
- relaying a protected envelope;
- providing a historical witness;
- executing an audit assignment;
- signing a bonded warranty;
- verifying a user-funded compute job.

These should generally be **requester-paid micropayments**. If the protocol subsidized every query receipt, one operator could manufacture both fake clients and fake servers and pay itself.

---

# 9. Verifier registry and bonds

Every paid verifier is represented by a first-class principal:

```text
VerifierProfile {
    verifier_principal
    supported_roles[]
    supported_proof_systems[]
    implementation_commitments[]
    service_bond_lots
    public_endpoint_commitment
    performance_root
    objective_fault_count
    active_assignments
}
```

The verifier receives a capability authorizing specific roles:

```text
VerifierCapability {
    role
    maximum_concurrent_assignments
    accepted_protocol_versions
    bond_reference
    expiry
}
```

## Bond lots

Use standardized service-bond lots.

One bond lot allows one bounded amount of concurrent verification work. More bond supports proportionally more assignments, but:

- does not increase reward per assignment;
- does not create governance power;
- does not increase consensus voting weight;
- does not give priority over a correct small verifier.

Splitting one bond among many Sybil identities produces no more total capacity than keeping it under one identity.

This will not prevent hidden common ownership, but it makes identity splitting economically neutral rather than profitable.

## Performance record

The protocol records only objective performance:

- assignments completed;
- deadlines met;
- challenges passed;
- incorrect attestations;
- bonds slashed;
- protocol versions supported;
- proof systems supported.

It should not create a universal social reputation score.

Performance history may reduce marketplace collateral requirements gradually, but it should not create permanent incumbency.

---

# 10. Reward allocation

I would fund the system through four separate streams.

## Protocol security pool

Funded by bounded issuance and the consensus component of transaction fees.

Suggested initial allocation:

| Purpose | Share |
|---|---:|
| Finality-verifier seat rewards | 70% |
| Random independent audits | 15% |
| Challenge and incident reserve | 10% |
| Independent clients and formal assurance | 5% |

These figures should be tested through economic simulation before being frozen.

## DA fee market

Funded directly by publishers and state users:

- sampling;
- temporary custody;
- retrieval;
- reconstruction;
- archival storage.

## Application assurance market

Funded by users, organizations, contracts and AI job escrows:

- replicated execution;
- attestation verification;
- additional verifier signatures;
- warranty bonds;
- evaluator fees;
- bridge verification.

## Slashing and bug-bounty reserve

Funded by:

- objective slashes;
- forfeited service bonds;
- a small security-reserve allocation;
- ecosystem security grants.

---

# 11. Avoid centralizing reward structures

Several seemingly reasonable incentive mechanisms would make the network worse.

## Do not reward the fastest verifier only

That rewards:

- colocation;
- expensive networking;
- private data feeds;
- central cloud infrastructure.

Selected verifiers should all receive the same base reward if they complete the task within the permitted window.

## Do not make verification reward proportional to stake

Stake may secure a bond, but the same verification task should not pay a large operator more than a small operator.

## Do not reward self-reported geography or client diversity

Those facts are difficult to verify and easy to spoof.

Support diversity through:

- independent-client funding;
- default delegation policies;
- conformance credentials;
- public concentration metrics;
- randomized work allocation.

## Do not rely exclusively on error bounties

If the system is healthy, errors are rare. A verifier still incurs costs every day.

Selected auditors need predictable base compensation.

## Do not inject invalid transitions into live state

Truebit-style forced-error concepts may be intellectually useful for incentive analysis, but deliberately placing ambiguous invalid transitions in the authoritative ledger creates unnecessary complexity and risk.

Synthetic verification challenges may be used in a separate conformance network, not in final state execution.

## Do not reward unlimited signatures

Paying every signature encourages Sybil identities and bloats the ledger.

Select a bounded committee and a fixed reward budget.

---

# 12. Recommended genesis configuration

A credible initial configuration would be:

| Parameter | Genesis proposal |
|---|---:|
| Finality verifier seats | 1,024 |
| Open audit-verifier registry | Permissionless |
| Audit assignments per block | 16–32 |
| Re-execution coverage | Approximately 10% block-equivalent |
| Alternate proof-verifier audits | At least 4 per block |
| DA sampling | Mandatory for finality validators |
| Hot custody assignments | Randomly rotated |
| Audit service bond | Small standardized bond lots |
| Challenge commit window | 1–2 blocks |
| Challenge reveal window | 2–8 blocks |
| Challenge reward | Base floor plus share of objective slash |
| Public-goods verification allocation | 5% of security pool |
| Passive light-client reward | None |
| User-paid verifier marketplace | Available from genesis |

During the first mainnet hardening period, active validators should still re-execute state transitions in addition to verifying the proof. Audit incentives become more important when the network later permits stateless proof-primary validators.

---

# The resulting verifier economy

The system would have six complementary incentives:

\[
\boxed{
\text{Self-protection}
+
\text{Duty rewards}
+
\text{Service fees}
+
\text{Audit stipends}
+
\text{Challenge bounties}
+
\text{Warranty premiums}
}
\]

Each solves a different problem:

- **Self-protection** motivates users and institutions to verify their own state.
- **Duty rewards** ensure consensus verifiers pay attention.
- **Service fees** compensate DA, retrieval and application-specific verification.
- **Audit stipends** keep independent checking profitable even when no one cheats.
- **Challenge bounties** create strong upside for finding actual failures.
- **Warranty premiums** allow high-value users to purchase additional bonded assurance.

The central economic principle should remain:

> **A verifier is paid not for saying “I checked,” but for accepting a measurable responsibility, producing an accountable result, and placing something at risk if that result is objectively false.**
