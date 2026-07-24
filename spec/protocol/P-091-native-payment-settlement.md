# P-091 — Native payment intents and settlement lifecycle

Status: development draft  
Schema revision: 1  
Tracking epic: [#189](https://github.com/advatar/ActiveChain/issues/189)

## 1. Scope

This specification freezes the first provider-independent ActiveBridge values:

- exact asset amounts;
- expiry-bounded quotes;
- merchant payment intents;
- external-evidence assurance classes;
- monotonic payment lifecycle records;
- durable idempotency bindings.

It does not authorize issuance, mutate Coin Cells, call providers, define connector JSON, or claim
that an external observation is ActiveChain finality. Those refinements require the native asset
registry, payment kernel, connector host, authenticated ingress, and proof-bearing RPC.

## 2. Security boundary

Consensus MUST NOT:

- call an external provider;
- parse provider-specific payloads;
- accept a provider status as block finality;
- identify an asset by display symbol;
- use floating-point money or exchange rates;
- infer a stronger evidence class from a weaker class.

Provider-specific code MUST remain outside validators. Consensus-visible payment values use the
canonical codec, explicit type tags, strict bounds, and trailing-data rejection.

## 3. Canonical identifiers and amounts

`PaymentIntentId`, `PaymentQuoteId`, `PaymentAttemptId`, `ConnectorId`, `RailId`, and `TreasuryId`
wrap one nonzero `Digest384`. Zero is invalid.

```text
AssetAmountV1 {
    asset: AssetId
    atomic_units: u128
}
```

Both fields MUST be nonzero. `atomic_units` uses the decimals fixed by the referenced asset
registry entry. Applications MUST NOT compare, add, or substitute amounts whose `AssetId` differs.

## 4. Quote

`PaymentQuoteV1` binds:

- chain, quote, merchant, connector, and source rail;
- exact source and settlement amounts;
- provider, connector, and maximum network fees;
- rational exchange-rate numerator and denominator;
- asset-policy revision;
- inclusive start and exclusive expiry;
- nonce and complete terms commitment.

All fees MUST use the settlement asset. Their checked total MUST be strictly less than the
settlement amount. Both exchange-rate terms MUST be positive. `valid_from` MUST be less than
`expires_at`.

Quote acceptance MUST sign or otherwise authorize the complete canonical quote commitment. A
connector MUST NOT silently change amount, asset, fee, rate, policy, route, or expiry.

## 5. Payment intent

`PaymentIntentV1` binds:

- chain, intent, merchant, and treasury;
- payer-reference and quote commitments;
- requested and minimum settlement;
- expiry and caller-chosen idempotency key;
- authorization-context and disclosure-policy commitments;
- callback and application-metadata commitments.

Requested and minimum settlement MUST reference the same asset. Minimum settlement MUST NOT exceed
requested settlement. Personal data, phone numbers, bank identifiers, callback URLs, and
application metadata remain outside the canonical value; commitments prevent substitution.

## 6. Evidence classes

Evidence classes are:

1. `UntrustedClientReport`
2. `ConnectorAuthenticated`
3. `ProviderSigned`
4. `RegulatedAttestation`
5. `ActiveChainFinalized`

The numeric order is an encoding convention, not an authorization rule. An asset policy MUST name
the class and verifier it accepts. No implementation may promote a class merely because its enum
tag is greater.

### 6.1 Provider observations

`ProviderObservationV1` binds the chain, connector, attempt, intent, provider account and reference
commitments, provider sequence and state, exact asset amount, occurrence/observation times,
assurance class, and complete payload commitment.

Provider observations MUST use `ConnectorAuthenticated`, `ProviderSigned`, or
`RegulatedAttestation`; they MUST NOT claim `ActiveChainFinalized`. Exact replay is idempotent.
A changed observation MUST preserve every operation binding, advance sequence by exactly one, and
never move connector observation time backwards.

## 7. Lifecycle

The canonical lifecycle states are:

```text
Created
  -> AwaitingPayer
  -> ProviderPending
  -> ExternallyConfirmed
  -> ChainSubmitted
  -> Finalized
  -> RefundPending
  -> Refunded
```

Declared failure/holding edges additionally enter `Expired`, `Rejected`, `Failed`, `Cancelled`, or
`ManualReview`. The production transition table is implemented by `PaymentState::permits`.

Each `PaymentLifecycleRecordV1` binds:

- intent;
- sequence;
- state;
- evidence class and exact observation commitment;
- optional transaction;
- optional finalized height and block;
- bounded reason code.

Successors MUST preserve the intent and increment sequence by exactly one. `Refunded`, `Expired`,
`Rejected`, `Failed`, and `Cancelled` are immutable terminal states.

`ChainSubmitted` MUST carry a nonzero transaction and MUST NOT carry finalized block evidence.
`Finalized` and `Refunded` MUST carry:

- `ActiveChainFinalized`;
- the exact nonzero transaction;
- a nonzero finalized height;
- a nonzero finalized block commitment.

No other state may carry `ActiveChainFinalized`. In particular, `ExternallyConfirmed` is not an
available wallet balance or finalized merchant settlement.

## 8. Idempotency

`IdempotencyBindingV1` binds:

- caller;
- idempotency key;
- exact canonical request-body commitment;
- resulting payment intent;
- creation and retention bounds.

The same caller and key with the same body returns the same intent. The same caller and key with a
different body MUST return `IdempotencyConflict`. Records MUST survive restart and remain until
after every configured provider retry, webhook, dispute, and reconciliation window.

The binding alone does not implement a durable store. The connector host and payment kernel must
persist it before releasing any effect that could move value.

The reference connector journal stores one latest observation per attempt in canonical attempt
order. It computes the complete successor in memory, writes a domain-separated checksummed
snapshot to a temporary file, calls `sync_all`, atomically renames it, and synchronizes the parent
directory before replacing live memory. Failed persistence MUST leave the prior in-memory state
unchanged. Corrupt, truncated, reordered, duplicate, or trailing snapshot data MUST fail closed.

## 9. Registered top-level types

| Type | Tag | Revision |
| --- | ---: | ---: |
| `PaymentQuoteV1` | `0x00f0` | 1 |
| `PaymentIntentV1` | `0x00f1` | 1 |
| `PaymentLifecycleRecordV1` | `0x00f2` | 1 |
| `IdempotencyBindingV1` | `0x00f3` | 1 |
| `ProviderObservationV1` | `0x00f4` | 1 |

Unknown enum tags, schema revisions, invalid values, non-minimal lengths, oversized bodies, and
trailing bytes MUST fail closed.

Deterministic accepted and malformed envelope material is published in
`testing/activebridge-payment-vectors-v1.tsv` and asserted directly by the Rust tests.

## 10. Required properties

The implementation and formal models must establish:

- terminal lifecycle immutability;
- exact monotonic sequencing;
- external observation cannot satisfy finality;
- finalized states contain exact transaction and block evidence;
- idempotency reuse cannot change the request body;
- asset identity and minimum-output bounds are preserved;
- fee arithmetic is checked and bounded;
- encoding round trips and malformed values fail deterministically.

## 11. Deferred refinements

Revision 1 intentionally defers:

- signatures and capability/APL authorization envelopes;
- provider observation schemas and connector compatibility manifests;
- native issuance, burn, redemption, refund, payout, and conversion transitions;
- durable connector and payment-kernel persistence;
- inclusion, state, and finality proof payloads;
- wallet, merchant, and SDK wire APIs;
- formal refinement from provider verification through finalized Coin Cell mutation.
