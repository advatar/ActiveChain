# ActiveBridge native payments, swaps, and merchant settlement

Status: implementation plan  
Tracking epic: [ActiveChain #189](https://github.com/advatar/ActiveChain/issues/189)  
Input: the product and integration recommendations in the locally supplied `nTZS.md`

## 1. Decision

ActiveChain should provide a native payment product surface without making any payment provider,
banking network, bridge, exchange, or regional aggregator part of consensus.

The system should have two deliberately separate layers:

1. **Native settlement primitives** define assets, authorization, conservation, payment intents,
   conversion, fees, receipts, and finalized state on ActiveChain.
2. **ActiveBridge connectors** translate external collection, payout, banking, mobile-money,
   custody, and liquidity events into those primitives under explicit trust and assurance classes.

nTZS is the first proposed regional connector because it can provide one integration for
Tanzanian mobile-money collection and payout plus TZS/stablecoin liquidity. It is not the
architecture. The same boundary must accommodate SEPA, ACH, Pix, UPI, cards, regulated token
issuers, exchanges, and other aggregators without changing consensus or the application-facing
payment lifecycle.

The intended developer experience is:

```text
Application or wallet
        |
        v
ActiveBridge payment API
        |
        +-- canonical quote and payment intent
        +-- capability and APL authorization
        +-- optional identity or eligibility proof
        +-- idempotent provider operation
        +-- native asset transition
        +-- finalized proof-bearing receipt
        |
        v
Merchant treasury and reconciliation
```

This plan copies the useful product concept identified in `nTZS.md`, not proprietary
implementation details.

## 2. Product outcome

A merchant should be able to:

1. create or discover an ActiveChain treasury;
2. request a bounded quote for a supported collection rail and settlement asset;
3. present a hosted, wallet-native, QR, deep-link, or server-to-server payment instruction;
4. receive authenticated progress events;
5. obtain a finalized ActiveChain receipt or an honest external-only terminal result;
6. refund or pay out under threshold and policy controls;
7. reconcile provider cash, connector accounting, native asset supply, fees, and merchant balance;
8. verify the resulting chain evidence offline.

An end user should be able to pay using an enabled regional rail and receive, hold, transfer, or
spend a protocol-native asset without visiting a DEX UI, changing wallets, acquiring gas first, or
understanding connector topology.

## 3. Boundaries and non-goals

### 3.1 Consensus boundary

Consensus validates only canonical ActiveChain facts:

- registered asset definitions and revisions;
- issuer and controller authority;
- authenticated, authorized state transitions;
- Coin Cell ownership and conservation;
- accepted oracle or attestation statements under declared policy;
- finalized conversion and settlement actions;
- fees, paymaster reimbursement, and receipts.

Consensus must not call an external API, wait for a webhook, resolve DNS, parse provider JSON, hold
provider credentials, or infer finality from a connector database.

### 3.2 Connector boundary

Connectors may:

- request external collections and payouts;
- poll or receive provider events;
- obtain quotes and execute conversions;
- verify provider signatures and certificates;
- map provider identifiers and states into bounded canonical observations;
- submit authorized ActiveChain actions;
- reconcile external and on-chain ledgers.

Connector observations are not finalized chain facts until the declared asset policy accepts them
and the corresponding transition finalizes.

### 3.3 Regulatory boundary

The protocol can enforce declared controls but does not itself become:

- a licensed payment institution;
- a bank or custodian;
- a stablecoin issuer;
- a reserve auditor;
- a sanctions-list authority;
- a foreign-exchange dealer;
- a guarantee of redemption or fiat parity.

Production deployment requires a lawful operator, issuer, reserve and redemption arrangements,
jurisdiction-specific compliance, provider contracts, operational controls, and independent audit.

### 3.4 Initial non-goals

- trustless bridging from arbitrary external chains;
- automatic listing of USDC, USDT, or any similarly named asset;
- treating a wrapped asset as identical to its external source asset;
- opaque best-price routing across unreviewed venues;
- credit, lending, chargeback insurance, or fractional reserves;
- a global identity database or disclosure of full KYC records on-chain;
- optimistic wallet balances presented as finalized funds.

## 4. Relationship to existing ActiveChain work

ActiveBridge depends on, rather than replaces, current work:

| Existing scope | Dependency |
| --- | --- |
| #163 multi-asset Coin Cells | Bind every balance and payment transition to an unambiguous `AssetId`. |
| #164 native asset tokenization | Register issuers, supply policy, controls, attestations, and redemption. |
| #165 tokenization identity | Apply selective-disclosure and ZK policy proofs without global KYC. |
| #167 testnet faucet | Reuse finalized funding status patterns; never reuse faucet mint authority. |
| Cash Plane | Reuse Coin Cells, fee inputs, channels, paymasters, sponsorship, and receipts. |
| APL and capabilities | Authorize merchant, issuer, connector, treasury, refund, and payout actions. |
| Proof-bearing RPC | Return finalized block, inclusion, state, protocol, and verifier evidence. |
| Wallet ABI | Discover assets, approve quotes, sign intents, and render honest lifecycle state. |
| Agent keys | Attenuate automation authority for treasury and reconciliation agents. |

No connector pilot may bypass unfinished multi-asset conservation, asset registry, transaction
ingress, or finalized owner-scoped discovery by storing a second authoritative balance database.

## 5. Canonical domain model

All consensus-visible types use the bounded canonical codec, explicit revisions, domain-separated
commitments, strict trailing-data rejection, and deterministic malformed vectors.

### 5.1 Identifiers

Define opaque, network-bound identifiers:

- `PaymentIntentId`
- `PaymentAttemptId`
- `PaymentQuoteId`
- `ConnectorId`
- `ProviderReference`
- `MerchantId`
- `TreasuryId`
- `RailId`
- `AssetId`
- `SettlementId`
- `RefundId`
- `PayoutId`
- `ReconciliationPeriodId`

Provider references must never be accepted as globally unique without `ConnectorId`, environment,
and provider-account binding.

### 5.2 Money

```text
AssetAmountV1 {
    asset_id: AssetId
    atomic_units: u128
}
```

Floating point is forbidden. Asset metadata fixes decimals, display symbol, issuer, lifecycle
policy, and revision. Display symbols such as `USDC` are not identities.

### 5.3 Quote

```text
PaymentQuoteV1 {
    network
    quote_id
    merchant
    connector
    source_rail
    source_amount
    settlement_amount
    provider_fee
    connector_fee
    network_fee_limit
    exchange_rate_numerator
    exchange_rate_denominator
    liquidity_source_class
    asset_policy_revision
    expires_at
    nonce
    terms_commitment
    signer
}
```

A quote commits to every user-visible amount, fee, rate, route class, validity bound, and policy
revision. Execution must fail closed if any bound changes.

### 5.4 Payment intent

```text
PaymentIntentV1 {
    network
    intent_id
    merchant
    treasury
    payer_reference_commitment
    quote_commitment
    requested_settlement
    minimum_settlement
    expiry
    idempotency_key
    authorization_context
    disclosure_policy
    callback_commitment
    metadata_commitment
}
```

Private payer data, phone numbers, bank identifiers, provider payloads, and merchant metadata stay
off-chain. Only the minimum binding commitments and accepted predicates enter the action.

### 5.5 State machines

Payment intent:

```text
created
  -> awaiting_payer
  -> provider_pending
  -> externally_confirmed
  -> chain_submitted
  -> finalized
  -> refund_pending
  -> refunded
```

Every state can also enter an explicitly reasoned `expired`, `rejected`, `failed`, `cancelled`, or
`manual_review` terminal/holding state where allowed. `externally_confirmed` is never displayed as
`finalized`.

`PaymentLifecycleJournalV1` stores one exact record per intent in canonical intent order. Initial
creation and every permitted next-sequence edge are synchronized and atomically replaced before
acknowledgement. Restart decoding preserves the record's evidence class, transaction, and finalized
evidence as encoded; it cannot promote an externally confirmed record to chain-submitted or
finalized. Duplicate or unknown intents, skipped sequences, illegal edges, corrupt storage, and
failed writes do not advance the live lifecycle.

Payout:

```text
requested -> approved -> funds_locked -> provider_pending -> externally_settled
          -> finalized | reversed | failed | manual_review
```

Conversion:

```text
quoted -> authorized -> input_locked -> venue_pending
       -> output_observed -> finalized | refunded | failed | manual_review
```

The specification must define allowed transitions, responsible actor, timeout, retry class,
compensating action, and terminal immutability for every edge.

### 5.6 Evidence classes

Every observation declares one of:

1. `untrusted_client_report`
2. `connector_authenticated`
3. `provider_signed`
4. `regulated_attestation`
5. `activechain_finalized`

Higher classes are not inferred from lower ones. Asset policy determines which evidence and
threshold authorize issuance, release, redemption, refund, or payout.

## 6. API surface

### 6.1 Public operations

Version the API independently from protocol revision:

```text
POST /v1/wallets
GET  /v1/assets
GET  /v1/rails
POST /v1/quotes
POST /v1/payment-intents
GET  /v1/payment-intents/{id}
POST /v1/payment-intents/{id}/cancel
POST /v1/refunds
GET  /v1/refunds/{id}
POST /v1/payouts
GET  /v1/payouts/{id}
POST /v1/conversions
GET  /v1/conversions/{id}
GET  /v1/treasuries/{id}/balances
GET  /v1/settlements/{id}
GET  /v1/reconciliation/periods/{id}
```

The REST facade is a developer-product boundary, not a consensus API. Native RPC exposes the
canonical request, status, receipt, and proof types underneath it.

### 6.2 Request rules

Every mutating request requires:

- authenticated merchant or delegated agent;
- capability and APL authorization;
- network and environment binding;
- body commitment;
- caller-chosen idempotency key;
- expiry and nonce;
- bounded request size;
- explicit expected asset and amount;
- optional approval bundle when policy requires it.

The same idempotency key with the same body returns the same operation. Reuse with a different body
is rejected. Idempotency records survive restart and are retained beyond all provider retry and
webhook windows.

`IdempotencyJournalV1` stores those bindings in canonical `(caller, idempotency_key)` order. A new
binding is synchronized and atomically replaced before its intent is returned; an identical retry
returns the original intent without rewriting state, while a different body fails without
mutation. Expired records remain binding until an explicit atomic prune succeeds, preventing an
implicit timeout race from assigning one caller/key pair to two operations. Corrupt restart data
and failed persistence fail closed.

Create-intent admission uses the stronger `PaymentRequestStateV1` crash-consistency unit. It joins
each immutable intent, its exact merchant-scoped idempotency binding to the domain-separated
canonical intent commitment, and its current lifecycle record. The three collections must contain
the same unique intent identities on creation and restart. `DurablePaymentRequestState` persists
the joined successor once before returning the intent; an exact retry reconstructs and returns the
original intent without rewriting, while merchant, key, body, expiry, partial-state, or intent-ID
substitution fails before memory or storage advances.

Every later lifecycle edge is also applied through `DurablePaymentRequestState`: the lifecycle
journal advances in a clone, the complete intent/binding/lifecycle invariant is revalidated, and
the whole joined snapshot is atomically replaced before live memory changes. A restart therefore
cannot observe a newer lifecycle with an absent intent or create binding, or an older lifecycle
after an acknowledged successor.

Finalized advancement additionally requires `PaymentFinalizedSettlementV1`, binding the exact
intent, negotiated native asset/amount, transaction, finalized height and block, receipt
commitment, and proof commitment. The joined request state checks the intent's settlement range,
requires the finalized transaction to equal the immediately preceding chain-submitted transaction,
derives the lifecycle observation commitment from the canonical evidence, and persists the whole
successor atomically. This object records proof-bearing facts but does not itself verify the proof:
`DurablePaymentRequestState::finalize_verified_settlement` first invokes the shared bounded verifier
against the trusted chain genesis. It requires the canonical receipt commitment, finality-proof
commitment, finalized block and height, and inclusion of the exact submitted transaction in the
receipt action set before the private state transition can run. Invalid proof bytes cannot mutate
the joined request state.

`PaymentSettlementStateV1` is the authoritative post-finality crash-consistency unit. It retains
the complete verified settlement object alongside the joined request state and initializes
`PaymentRefundStateV1` with that exact evidence commitment and settled amount in the same atomic
replacement. On restart, every finalized/refund lifecycle must resolve to one unique settlement,
and every settlement must resolve to matching refund accounting. The public durable aggregate owns
intent creation, lifecycle advancement, and verify-then-finalize; the older request-only boundary
cannot publicly finalize commitment-only state.

### 6.3 Status and receipt rules

Status responses identify:

- last accepted lifecycle state and sequence;
- whether the statement is connector-only or chain-finalized;
- exact quote and intent commitments;
- provider reference commitment where disclosure is permitted;
- submitted action or transaction;
- finalized height and block hash;
- inclusion and state evidence;
- protocol, schema, API, connector, and verifier revisions;
- error taxonomy and retry guidance.

Offline verification must not require trusting the connector that served the receipt.

### 6.4 Webhooks

Webhook envelopes include:

- event identifier and monotonic operation sequence;
- event type and canonical status commitment;
- merchant and environment;
- creation and expiry timestamps;
- key identifier and PQ signature profile;
- delivery attempt identifier;
- API and schema revisions.

Consumers acknowledge at least once and deduplicate by event identifier. Ordering is guaranteed
only per operation. A webhook is a notification to query canonical status, not settlement proof.
The canonical delivery envelope commits its ML-DSA-44 transport signer and signs a
domain-separated encoding of the complete event. The connector host verifies that signature before
atomically persisting the exact next per-subscription cursor; forged, substituted, replayed, or
out-of-order events cannot advance acknowledgement state. Transport authentication does not change
the embedded evidence class or confer ActiveChain finality.

## 7. Connector contract

### 7.1 Required interface

```text
PaymentConnector {
    capabilities()
    health()
    create_collection()
    resolve_collection()
    create_payout()
    resolve_payout()
    quote_conversion()
    execute_conversion()
    resolve_conversion()
    cancel_if_supported()
    ingest_event()
    reconcile()
}
```

Each method accepts and returns bounded canonical host types. Provider-specific JSON remains inside
the connector adapter.

### 7.2 Isolation

Connectors run outside validators in a restricted host:

- no consensus-process linkage;
- per-connector service identity;
- outbound destination allowlist and DNS pinning policy;
- secrets from an operator-configured secret provider;
- encrypted durable journal;
- bounded CPU, memory, request size, concurrency, and deadlines;
- no arbitrary dynamic plugin loading in the initial release;
- signed connector binary and compatibility manifest;
- append-only security and reconciliation audit events.

Wasm components may be considered later for portable adapters, but the first implementation should
use reviewed Rust services with explicit network and secret boundaries.

### 7.3 Operator configuration

Operators configure:

- enabled connectors, environments, rails, directions, and asset pairs;
- provider endpoints and account references;
- secret references, never secret values in committed configuration;
- collection, payout, conversion, treasury, and daily limits;
- fee schedules and quote validity;
- minimum confirmations or provider evidence class;
- liquidity venues and maximum slippage;
- retry, timeout, circuit-breaker, and manual-review thresholds;
- webhook delivery policy;
- retention and redaction policy;
- maintenance and kill switches.

Configuration is schema-versioned, validated before activation, committed for audit, and supports
safe staged rollout. A global emergency stop prevents new operations while preserving status,
reconciliation, refund, and recovery access.

### 7.4 nTZS reference connector

The nTZS connector should begin against a contractual sandbox and implement only documented,
verified capabilities. Before coding it, obtain:

- current official API and webhook specifications;
- sandbox credentials and service-level expectations;
- authentication, signing, replay, and IP allowlisting rules;
- supported provider/rail matrix;
- currencies, decimals, fees, limits, and settlement timing;
- idempotency and duplicate-event behavior;
- status and error taxonomy;
- refund, reversal, payout, and reconciliation semantics;
- custody, stablecoin, reserve, redemption, and chain-settlement disclosures;
- production onboarding and regulatory responsibilities.

Map every provider state explicitly. Unknown states enter `manual_review`; they are never coerced
to success. Record fixture payloads only after removing credentials and personal data. Contract
tests must run against a deterministic simulator so CI never depends on an external service.

## 8. Native settlement

### 8.1 Asset representation

An externally sourced asset is represented by a registered native `AssetId` whose definition names:

- issuer and controller principals;
- monetary unit and decimals;
- issuance, burn, and redemption authority;
- accepted evidence policies;
- reserve/attestation policy where applicable;
- freeze, deny, recovery, and upgrade controls;
- jurisdiction and credential policy commitments;
- canonical external-reference class;
- migration and shutdown behavior.

The registry must prevent symbol collision and false equivalence. A TZS asset issued against nTZS
evidence is distinct from another TZS-denominated liability unless an explicit conversion exists.

### 8.2 Ingress

For externally backed issuance:

1. create a payment intent;
2. obtain authenticated external collection evidence;
3. verify freshness, amount, currency, provider account, intent, and non-reuse;
4. satisfy issuer capability, APL, and approval policy;
5. submit a native issuance or treasury-transfer transition;
6. finalize the transition;
7. return proof-bearing status.

Exactly one external collection reference may authorize value-bearing issuance. Duplicate,
reordered, delayed, substituted, or conflicting evidence fails closed.

### 8.3 Egress

For redemption or payout:

1. lock or burn the exact native asset amount;
2. finalize authorization before releasing provider funds unless a declared prefunding profile
   applies;
3. submit the provider payout idempotently;
4. reconcile external completion;
5. finalize the receipt or execute the specified compensating transition.

The design must state who bears risk between chain finalization and provider completion.

### 8.4 Conversion

Initial conversion is quote-driven and uses one configured venue at a time. The action commits to:

- input and minimum output;
- all fees;
- maximum slippage;
- venue class;
- deadline;
- refund destination;
- settlement policy.

Multi-venue routing follows only after deterministic quote comparison, failure isolation, and
formal conservation/refund properties exist. “Atomic” must not be claimed across an external venue
unless the external leg is cryptographically atomic under a reviewed protocol.

Refund execution maintains one bounded, canonically ordered state per finalized payment intent.
`RefundJournalV1` atomically persists both settlement registration and every cumulative partial-
refund successor before acknowledgement. Each request must bind the exact settlement, asset,
expected refunded total, next sequence, and active window; unknown intents, duplicate registration,
replay, over-refund, corrupt restart state, and failed writes do not advance live accounting. This
durability proves refund replay safety only—it does not promote an external payout observation to
finalized ActiveChain settlement.

The durable complete-settlement aggregate is the public refund-request boundary. Its first accepted
partial refund atomically joins the `Finalized -> RefundPending` lifecycle edge, a domain-separated
commitment to the canonical request, and the cumulative refund successor in one snapshot. Later
partials retain that lifecycle evidence while advancing only the exact amount and request sequence;
no standalone refund journal write can partially advance the public settlement state.

Disputes use a separate `DisputeJournalV1`, canonically ordered by immutable dispute identity. The
journal atomically persists opening and each exact next-sequence lifecycle successor, and restart
decoding retains the evidence class that distinguishes client reports, connector-authenticated
external resolution, chain submission, and finalized ActiveChain evidence. Duplicate or unknown
disputes, wrong-intent substitution, skipped sequences, illegal state edges, corruption, and failed
writes do not advance live state. The public complete-settlement aggregate retains this journal
beside the exact verified settlement, request lifecycle, and refund accounting; dispute opening must
bind that settlement's commitment, native asset, and a bounded amount. Advancing a dispute replaces
the same aggregate snapshot and never changes or promotes the payment lifecycle's finality.
writes do not advance the live record.

### 8.5 Gas sponsorship

Reuse Cash Plane paymasters:

- merchant or connector supplies native fee inputs;
- the user signs the payment intent, not an ambient spending authorization;
- reimbursement in the payment asset is bounded by the signed quote;
- sponsorship failure cannot debit the user;
- receipts separate provider, connector, paymaster, and protocol fees.

## 9. Authorization, identity, and privacy

Define separate capabilities for:

- quote issuance;
- collection observation;
- native issuance and burn;
- payout initiation;
- conversion;
- treasury transfer;
- refund;
- reconciliation;
- configuration and emergency stop.

High-risk actions use threshold approval, amount/time budgets, asset and destination constraints,
and hardware-backed operator keys where supported. Agent principals receive attenuated,
revocable, expiring capabilities; they never receive a treasury root key.

`TreasuryJournalV1` persists the bounded policy set in canonical `TreasuryId` order. Registration
and each authorized payout, conversion, refund, fee, or settlement debit are synchronized and
atomically replaced before acknowledgement, carrying the exact spent budget and next nonce across
restart. Duplicate or unknown treasuries, stale commitments, wrong operators/assets/periods,
amount or period-budget overruns, replay, corruption, and failed writes cannot advance live policy.

Identity policy should consume minimal predicates such as:

- residency or permitted-jurisdiction membership;
- non-membership in prohibited jurisdiction sets;
- age threshold;
- business or merchant status;
- transaction-limit eligibility;
- sanctions-screening attestation freshness.

Full credentials, mobile numbers, account identifiers, provider payloads, and exact attributes stay
off-chain. Presentation requests bind audience, action, asset, amount class, nonce, policy revision,
expiry, holder key, and credential-status evidence. The privacy review must address correlation
across merchant, connector, issuer, and chain identifiers.

## 10. Treasury and merchant controls

Treasuries are native objects with:

- accepted asset and rail policy;
- settlement asset preference;
- automatic conversion limits;
- payout destinations;
- daily and per-operation budgets;
- approval thresholds;
- agent capabilities;
- reserve and working-capital partitions;
- reconciliation and reporting policy;
- recovery and freeze controllers.

Merchant tooling provides:

- live, honest available/pending/finalized balances;
- payment, refund, payout, and conversion timelines;
- quote and fee inspection;
- approval inbox;
- reconciliation exceptions;
- connector health and maintenance status;
- downloadable signed reports and offline-verifiable receipts;
- emergency-stop and key-recovery workflows.

## 11. Persistence and reconciliation

Use a transactional journal with checksummed snapshots and atomic replacement. Persist before
releasing any outbound provider request, chain submission, approval, or terminal response whose
duplication could move value.

Reconciliation compares four ledgers:

1. provider collections/payouts;
2. connector operation journal;
3. ActiveChain finalized actions and Coin Cells;
4. merchant treasury accounting.

Every period produces a signed report with opening balance, collections, payouts, issuance, burns,
conversions, fees, reversals, exceptions, and closing balance by asset. Differences never
auto-resolve by minting, burning, or editing history. They enter bounded manual review with
dual-control remediation.

Backups, restore, and disaster recovery must prove:

- no loss of idempotency records;
- no replay of external evidence;
- no duplicate payout or issuance;
- exact operation sequence recovery;
- reconciliation continuity;
- secret rotation without loss of status resolution.

## 12. Security and threat model

The threat model includes:

- forged, replayed, reordered, delayed, and duplicated provider events;
- compromised connector, merchant, issuer, paymaster, liquidity venue, or webhook endpoint;
- DNS, TLS, certificate, routing, and dependency compromise;
- secret leakage and confused environment/account selection;
- amount, decimal, symbol, asset, destination, or quote substitution;
- malicious callback URLs and server-side request forgery;
- partial provider success followed by timeout;
- chain submission retry, reorganization, stale proof, or wrong-network response;
- payout races, refund duplication, and conversion under-delivery;
- insolvency, reserve mismatch, provider freeze, and redemption outage;
- privacy correlation and log/backup leakage;
- operator misconfiguration and unsafe software upgrade.

Release gates require secret scanning, dependency pinning, signed artifacts, SBOMs, reproducible
builds, fuzzing, penetration testing, independent protocol/connector review, incident exercises,
and a public limitations statement.

## 13. Formal verification program

Formal work is mandatory for every value-moving layer.

### 13.1 State-machine properties

Model in Lean and/or TLA+:

- lifecycle transitions are total and terminal states immutable;
- sequence numbers are monotonic;
- the same idempotency key cannot produce two effects;
- one provider evidence reference cannot authorize two issuances;
- accepted amount, asset, merchant, and destination match the signed intent;
- payout and refund paths cannot both release the same locked value;
- retries and restart are observationally equivalent to one uninterrupted execution;
- emergency stop prevents new risk while preserving recovery.

### 13.2 Arithmetic and conservation

Prove or bounded-model-check production arithmetic:

```text
inputs + authorized issuance
= outputs + authorized burn + explicit fees
```

Also prove:

- no overflow or decimal reinterpretation;
- output is never below signed minimum;
- fees never exceed signed maxima;
- quote rational arithmetic rounds in the declared direction;
- supply registry and Coin Cell totals remain consistent;
- compensation cannot create value.

### 13.3 Authorization and refinement

Prove the refinement chain:

```text
authenticated external evidence
  -> canonical observation
  -> accepted asset policy facts
  -> capability and APL decision
  -> exact native transition
  -> finalized receipt
```

Publish every assumption: provider honesty, cryptographic verification, trusted roots, clocks,
filesystem atomicity, secret hardware, compiler/toolchain, operator policy, and external
regulatory facts. Formal verification does not prove reserve solvency or provider honesty.

### 13.4 Deterministic vectors

Publish positive and malformed vectors for:

- types and commitments;
- quote and intent signatures;
- webhook envelopes;
- provider-state mappings;
- evidence-to-transition binding;
- issuance, payout, refund, conversion, and paymaster accounting;
- finality and offline receipt verification;
- upgrade and backward-compatibility behavior.

## 14. Testing strategy

### 14.1 Unit and property tests

Each crate includes:

- canonical round trips and trailing-data rejection;
- bounds and allocation limits;
- state transition tables;
- idempotency and replay;
- checked arithmetic and rounding;
- policy/capability attenuation;
- redaction and log-safety tests.

### 14.2 Connector contract suite

A reusable simulator drives:

- success, pending, rejection, cancellation, timeout, and reversal;
- duplicate and out-of-order webhooks;
- unknown statuses and fields;
- signature and certificate failure;
- inconsistent quote/settlement amounts;
- rate limits and retry advice;
- partial payout and ambiguous completion;
- sandbox/production and provider-account substitution;
- reconciliation-file corruption and omission.

Every connector must pass the same suite before provider-specific tests.

### 14.3 End-to-end qualification

Test:

- collection to finalized native asset;
- native redemption to completed payout;
- stable-asset payment with sponsored gas;
- conversion with minimum-output protection;
- refund and dispute;
- treasury threshold approval;
- connector crash at every durable boundary;
- node and connector upgrade;
- wallet offline/reconnect;
- provider outage and chain outage;
- reconciliation and restore from backup;
- offline receipt verification by an independent client.

Chaos tests inject process death, disk-full, torn writes, packet loss, clock skew, duplicate
delivery, stale DNS, slow provider responses, and reorganization within the supported finality
model.

## 15. Repository shape

Proposed packages, created only as their dependency milestone starts:

```text
spec/protocol/P-091-native-assets-and-payment-settlement.md
spec/protocol/P-092-activebridge-observations.md
crates/payment-types/
crates/payment-kernel/
crates/payment-connector-sdk/
services/activebridge-host/
connectors/ntzs/
tools/payment-vector-generator/
sdk/typescript/
sdk/swift/
sdk/kotlin/
mobile/apple/WalletApp/
mobile/android/
formal/lean/ActiveChain/Payments.lean
formal/tla/ActiveBridgeLifecycle.tla
formal/kani/
```

Consensus-critical code stays `no_std` and safe Rust. Networked connectors do not become workspace
dependencies of the consensus kernel.

## 16. Dependency-ordered delivery plan

### Milestone 0 — discovery and contract validation

Deliverables:

- provider-independent requirements and threat model;
- current nTZS API, legal, custody, settlement, and operational due diligence;
- glossary and trust/assurance classes;
- architecture decision records for native versus external state;
- test merchant and sandbox operating agreement;
- data-protection and regulatory responsibility matrix.

Exit criteria:

- no undocumented provider capability is in the plan;
- all external trust assumptions and manual operations are explicit;
- test data, retention, incident contacts, and service limits are agreed;
- unresolved legal or provider questions block only the affected connector, not core schemas.

### Milestone 1 — canonical schemas and lifecycle

Deliverables:

- `P-091` native payment settlement draft;
- `P-092` external observation and connector contract draft;
- payment types crate;
- deterministic vectors and state-machine reference model;
- error, retry, status, and idempotency contracts;
- compatibility and migration rules.

Exit criteria:

- specifications cover every state and abort path;
- codec, malformed, property, Lean/TLA+, and compatibility tests pass;
- security and wallet reviewers approve the frozen v1 boundary.

### Milestone 2 — native multi-asset foundation

Deliverables:

- complete #163 and the fungible subset of #164;
- asset-bound Coin Cells and supply registry;
- issuer/controller capabilities and APL hooks;
- owner-and-asset proof-bearing discovery;
- wallet ABI and offline verifier support;
- test ACT, test-EUR, and test-USD assets with unmistakable test metadata.

Exit criteria:

- conservation and cross-asset substitution proofs pass;
- finalized issuance, transfer, burn, redemption, and discovery work end to end;
- no wallet or RPC path fabricates balance or issuer claims.

### Milestone 3 — connector host and simulator

Deliverables:

- payment connector SDK;
- isolated host with durable journal, secret references, allowlists, limits, health, and kill switch;
- deterministic reference connector simulator;
- webhook ingestion/delivery and reconciliation engine;
- operator configuration schema and runbooks.

Exit criteria:

- contract suite, restart, corruption, SSRF, replay, and secret-rotation tests pass;
- connector compromise cannot sign arbitrary user or treasury transitions;
- operators can safely disable new operations and reconcile existing ones.

### Milestone 4 — nTZS sandbox connector

Deliverables:

- reviewed mappings for supported collection, payout, quote/conversion, and status operations;
- signature/authentication and webhook verification;
- sanitized fixtures and sandbox contract tests;
- rail/currency/limit capability discovery;
- reconciliation import and exception handling.

Exit criteria:

- all supported provider states map without ambiguity;
- duplicate/reordered events and timeout-after-success do not duplicate value movement;
- no production, reserve, redemption, or regulatory claim exceeds obtained evidence.

### Milestone 5 — native ingress, egress, conversion, and sponsorship

Deliverables:

- evidence-authorized issuance or treasury release;
- lock/burn-before-payout flow and compensating transitions;
- bounded conversion action;
- stable-asset paymaster reimbursement;
- proof-bearing finalized receipts;
- formal arithmetic, idempotency, and refinement artifacts.

Exit criteria:

- end-to-end simulator transactions conserve every asset;
- no external-only success appears as chain finality;
- crash and retry at every boundary produce at most one economic effect;
- offline verifier accepts valid receipts and rejects substitutions.

### Milestone 6 — developer, wallet, and merchant experience

Deliverables:

- authenticated REST/RPC gateway;
- TypeScript, Swift, and Kotlin SDKs;
- wallet funding, payment, approval, refund, payout-status, and receipt UX;
- merchant treasury and reconciliation console;
- sandbox quickstart, API reference, examples, and migration guide.

Exit criteria:

- a new sandbox merchant completes documented flows without internal tooling;
- accessibility, localization, privacy, and no-placeholder UI tests pass;
- SDK conformance and deterministic vectors agree across languages.

### Milestone 7 — Kanalen pilot

Deliverables:

- operator-configured testnet deployment;
- test assets only;
- bounded pilot merchants and users;
- telemetry, alerts, dashboards, backup/restore, and incident drills;
- published limitations, connector status, and verifier parameters.

Exit criteria:

- sustained soak, chaos, recovery, and reconciliation pass;
- supply and provider reports reconcile for every period;
- security/privacy review has no unresolved critical or high findings;
- kill switch and manual recovery are rehearsed.

### Milestone 8 — production qualification

Deliverables:

- finalized issuer/provider/operator agreements;
- independent audits of protocol, connector, operations, privacy, and formal claims;
- key ceremonies, HSM policy, disaster recovery, and business-continuity evidence;
- staged limits, bug bounty, incident disclosure, and upgrade policy;
- production compatibility manifest and signed release.

Exit criteria:

- lawful operators explicitly accept custody, reserve, redemption, compliance, and loss allocation;
- independent audits and remediation are complete;
- release council approves narrowly bounded assets, rails, limits, and jurisdictions;
- no production-readiness claim relies solely on testnet behavior or formal models.

## 17. Work breakdown and ownership

Split #189 into one implementation issue per milestone or independently reviewable package:

| Work package | Primary owner | Mandatory reviewers |
| --- | --- | --- |
| Protocol schemas and vectors | Protocol semantics | Cash, formal methods, wallets |
| Multi-asset and supply registry | Cash/state | Security, formal methods |
| Connector SDK and host | Integrations | Security, SRE |
| nTZS connector | Integrations | Provider, security, payments operations |
| Native settlement/refinement | Cash/transition | Formal methods, consensus |
| RPC and SDKs | Developer platform | Wallets, compatibility |
| Wallet and merchant UX | Client teams | Privacy, accessibility, operations |
| Reconciliation and treasury | Payments operations | Finance/control, security |
| Testnet and production rollout | SRE/release | Security, protocol, legal/compliance |

The author of a normative specification must not be the sole reviewer of both its implementation
and conformance tests.

## 18. Metrics

Track:

- quote latency and expiry rate;
- collection/payout/conversion completion time by rail;
- chain-finalization latency;
- duplicate/replay rejection count;
- ambiguous and manual-review rate;
- reconciliation differences by asset and provider;
- connector uptime and circuit-breaker state;
- effective user fees and conversion slippage;
- webhook delivery and consumer lag;
- supply/attestation freshness;
- privacy and security incidents;
- restore and incident-drill recovery time.

Do not combine off-chain provider throughput, payment-channel throughput, and base-layer finalized
transactions into one TPS number.

## 19. Open decisions

Resolve before freezing the relevant milestone:

1. Which entity issues each TZS, EUR, or USD-denominated native asset?
2. Does ingress mint new supply or release pre-minted treasury inventory?
3. Which provider evidence class and approval threshold authorize each action?
4. Who bears loss during external/chain partial failure and payout reversal?
5. Which external assets, chains, custodians, and redemption paths are acceptable?
6. Which conversion venues and rate sources may operators configure?
7. Which jurisdiction and credential predicates apply to each rail and asset?
8. Which data must be retained for regulation, and where can commitments replace personal data?
9. What are the initial limits, fees, supported rails, and pilot participants?
10. Does nTZS expose sufficient sandbox, signing, reconciliation, and operational contracts to be
    the first connector, or should the simulator and another provider lead?

## 20. Definition of done

ActiveBridge v1 is done only when:

- canonical schemas, lifecycle, trust classes, and compatibility policy are frozen;
- native multi-asset issuance, transfer, redemption, and discovery are finalized and verified;
- connector retries, restarts, and duplicate events cannot duplicate economic effects;
- every amount, fee, route, policy, and destination is user- or merchant-authorized;
- wallets distinguish pending external observations from finalized ActiveChain assets;
- merchants can reconcile provider, connector, chain, and treasury ledgers;
- deterministic vectors pass in Rust, TypeScript, Swift, and Kotlin;
- formal claims and assumptions are published and linked to production code;
- Kanalen pilot qualification and independent review are complete;
- production operation is gated by explicit issuer, provider, regulatory, reserve, security, and
  release approvals.
