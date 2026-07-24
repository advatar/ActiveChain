# P-092 — ActiveBridge external observations and nTZS sandbox profile

Status: draft implementation contract
Revision: 1
Reviewed provider documentation: 2026-07-24
Provider source: <https://www.ntzs.co.tz/developers>

## 1. Scope

This specification freezes how an isolated ActiveBridge connector may translate authenticated
external-provider statements into `ProviderObservationV1`. It does not make the external provider
part of ActiveChain consensus, establish the provider's custody or reserve claims, or authorize
Coin Cell issuance, release, burn, redemption, or finality.

The nTZS profile is intentionally sandbox-only. Production enablement requires separate legal,
security, operational, custody, reconciliation, and provider-contract qualification.

## 2. Trust boundary

An accepted nTZS webhook proves only that:

1. the connector received an HMAC matching its configured shared webhook secret;
2. the signature covered the exact ASCII timestamp, one `.` byte, and the exact raw body bytes;
3. the signed timestamp passed the operator's bounded freshness policy;
4. the JSON used a supported event type and its documented provider-reference field;
5. the event identity had not already crossed the durable replay barrier.

It does not prove that the provider is honest, that an external chain transaction is finalized,
that mobile-money settlement is irreversible, that reserves exist, or that an ActiveChain
transition finalized. HMAC is shared-secret authentication, so accepted events use
`connector_authenticated`, never `provider_signed` or `activechain_finalized`.

## 3. Fixed provider origin and credentials

The revision-1 adapter permits only:

```text
https://www.ntzs.co.tz
```

and the reviewed `/api/v1/...` endpoint templates. It accepts only the documented `ntzs_test_`
credential class for authenticated sandbox calls. Live credentials are rejected before transport.
The public swap-rate endpoint may be called without a key. Keys are passed ephemerally to an
operator transport and must not be embedded in mobile clients, persisted in requests, or logged.

The connector crate intentionally provides no HTTP client. The operator transport must provide
TLS verification, DNS/IP policy, timeouts, response-size enforcement, proxy policy, secret
injection, and audit logging without secret material.

## 4. Reviewed endpoint matrix

| Operation | Method | Path template | Authentication | Idempotency |
| --- | --- | --- | --- | --- |
| Create user | POST | `/api/v1/users` | test bearer key | provider says external ID is idempotent |
| Get user | GET | `/api/v1/users/{id}` | test bearer key | read |
| Deposit | POST | `/api/v1/deposits` | test bearer key | not documented |
| Transfer | POST | `/api/v1/transfers` | test bearer key | not documented |
| Withdrawal | POST | `/api/v1/withdrawals` | test bearer key | quote contract not frozen here |
| Swap rate | GET | `/api/v1/swap/rate` | none | read; short-lived quote |
| Swap | POST | `/api/v1/swap` | test bearer key | SSE; not documented |
| Ramp balance | GET | `/api/v1/ramp/balance` | test bearer key and capability | read |
| Ramp quote | POST | `/api/v1/ramp/quote` | test bearer key and capability | short-lived quote |
| Ramp off-ramp | POST | `/api/v1/ramp/offramp` | test bearer key and capability | required header |
| Ramp on-ramp | POST | `/api/v1/ramp/onramp` | test bearer key and capability | required header |
| Ramp settlement | GET | `/api/v1/ramp/{id}` | test bearer key and capability | read |
| Ramp settlements | GET | `/api/v1/ramp/settlements` | test bearer key and capability | read |

An adapter must not invent idempotency guarantees for operations where the reviewed contract does
not publish one. Such operations require connector-owned attempt persistence and reconciliation
before safe retries.

## 5. API/SSE status normalization

Only the exact case-sensitive states below are recognized:

| Operation | Provider status | ActiveBridge state | Rationale |
| --- | --- | --- | --- |
| deposit | `submitted` | `pending` | payer/provider work remains |
| transfer | `completed` | `succeeded` | provider reports external completion |
| withdrawal | `requested` | `pending` | approval/payout remains |
| withdrawal | `burned` | `pending` | burn is not proof of recipient payout |
| swap | `CHECKING` | `pending` | preflight |
| swap | `SENDING` | `pending` | first transfer |
| swap | `FILLING` | `pending` | second transfer |
| swap | `FILLED` | `succeeded` | provider reports fill |
| swap | `FAILED` | `rejected` | provider reports failure |
| ramp | `paying_out` | `pending` | payout remains |
| ramp | `minting` | `pending` | delivery remains |
| ramp | `completed` | `succeeded` | provider reports completion |
| ramp | `failed` | `rejected` | provider reports failure |

Every other operation/status pair maps to `unknown`, which enters manual review at the payment
lifecycle boundary. In particular, `deposit` API status `completed` is not accepted merely by
analogy; completion is admitted only through the separately authenticated documented webhook.

## 6. Webhook admission

Revision 1 accepts only the events for which the reviewed provider page publishes reference data:

| Event | Reference field | Observation |
| --- | --- | --- |
| `deposit.completed` | `data.depositId` | external `succeeded` |
| `transfer.completed` | `data.transferId` | external `succeeded` |
| `withdrawal.completed` | `data.withdrawalId` | external `succeeded` |

Although the provider page names ramp completion/failure event names, it does not publish their
event-data schema. They remain unsupported until a contractual schema supplies an immutable
settlement identifier and exact amount/asset bindings.

Admission order is:

1. bound raw-body size;
2. parse and bound the timestamp header;
3. apply past-age and future-skew limits;
4. decode the exact 32-byte hexadecimal signature;
5. verify HMAC-SHA256 over `timestamp || "." || raw_body`;
6. parse JSON and require an exact supported event/reference;
7. derive domain-separated payload, provider-reference, and replay commitments;
8. durably record the event-type/reference replay identity;
9. construct a connector-authenticated observation from independently stored attempt bindings;
10. let the payment kernel validate sequencing and policy before any native state transition.

The body is never reserialized before signature or payload commitment. Duplicate reference
identities are rejected across restart even if the delivery timestamp or JSON formatting changes.

## 7. Errors and unknown extensions

The exact reviewed error codes are:

```text
missing_required_fields
invalid_amount
invalid_transfer
wallet_not_provisioned
insufficient_balance
user_not_found
unauthorized
relayer_unavailable
blockchain_error
network_error
```

Unknown error strings remain `unknown`; they do not inherit retry, rejection, or success behavior.
HTTP timeouts, malformed responses, oversized responses, transport failures, and status extensions
are indeterminate until reconciled. Timeout-after-provider-success must reuse the durable attempt
record and poll/reconcile; it must not create a second economic attempt.

## 8. Amounts and assets

nTZS documentation presents TZS integer fields as well as decimal USDC/USDT examples. Provider
JSON numbers and token symbols are not canonical ActiveChain amounts or asset identities. This
profile never converts provider values through binary floating point.

Revision 1 parses provider numbers as bounded unsigned base-10 coefficient/scale pairs. It rejects
signs, exponent notation, leading-zero ambiguity, zero, overflow, excess syntactic precision, and
precision above the registered native asset scale. Atomic conversion is:

```text
atomic_units = coefficient * 10^(asset_decimals - provider_scale)
```

with checked arithmetic. TZS `amountTzs` is admitted only as a syntactic integer. USDC admits up to
the documented six decimal places. USDT amount binding remains unsupported because the reviewed
transfer response contract does not publish it.

The implemented core response profiles are:

| Operation | Reference | State | Amount |
| --- | --- | --- | --- |
| deposit | `id` | `status` | integer `amountTzs` |
| transfer, native | `id` | `status` | integer `amountTzs` when `token` is absent |
| transfer, USDC | `id` | `status` | `amount` with exact `token: "usdc"` |
| withdrawal | `id` | `status` | integer `amountTzs` |

Swap and ramp response bodies remain unsupported until their authoritative amount/reference schemas
are frozen. Unknown statuses in otherwise valid core responses still map to `unknown`.

An observation receives its expected `AssetId`, atomic-unit amount, and provider-reference
commitment from the pre-authorized persisted ActiveBridge attempt. The connector validates exact
unit, asset identifier, converted atomic quantity, and reference equality before it can emit an
observation. Provider fields never select a native asset merely by symbol.

## 9. Replay persistence and recovery

The reference replay journal stores a sorted, unique, bounded set of domain-separated event
identities. Snapshots use atomic write, file sync, rename, and parent-directory sync. A
domain-separated SHAKE256 tag detects accidental corruption; it is not a secret authenticator.
Corruption, capacity exhaustion, noncanonical ordering, duplicate entries, and failed persistence
fail closed without mutating in-memory state.

Production deployment still requires single-writer locking or a transactional store, backup and
restore exercises, retention policy, encrypted storage as appropriate, and reconciliation after
crash or failover.

## 10. Qualification gates

The sandbox adapter is not production-qualified until all of the following are evidenced:

- contractual sandbox credentials and non-production test execution;
- authoritative schemas for every enabled response, webhook, amount, fee, and identifier;
- provider retry, duplicate, ordering, reconciliation, reversal, and timeout semantics;
- settlement/custody/reserve/redemption and regulatory due diligence;
- connector-host SSRF, DNS rebinding, TLS, proxy, secret-rotation, and kill-switch tests;
- amount/asset binding and native settlement authorization;
- durable concurrency and disaster-recovery qualification;
- fuzzing, penetration review, and independent security audit.

## 11. Deterministic artifacts

- Rust adapter and unit tests: `connectors/ntzs/`
- sanitized webhook fixtures: `connectors/ntzs/fixtures/`
- mapping vectors: `testing/ntzs-provider-contract-v1.tsv`,
  `testing/ntzs-amount-vectors-v1.tsv`
- executable abstract model: `formal/lean/ActiveChain/Payments.lean`
- explicit proof boundary: `formal/ACTIVEBRIDGE_NTZS_PROOF_SCOPE.md`
