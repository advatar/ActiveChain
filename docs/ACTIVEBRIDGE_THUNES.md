# ActiveBridge Thunes Money Transfer v2 connector

Status: developmental integration for issue #803. This is an out-of-consensus rail adapter and does not claim a Thunes partnership, regulatory approval, production readiness, or ActiveChain finality from provider status.

## Provider boundary

Thunes Money Transfer API v2 uses the `/v2/money-transfer` prefix and HTTP Basic Authentication. Thunes provides the production and pre-production HTTPS origins during account onboarding. The ActiveBridge connector host must keep those origins in `ConnectorHostPolicyV1`, resolve the API key and secret from an opaque secret handle, enforce connection/request deadlines, and never place credentials or raw provider JSON in consensus state.

The adapter deliberately has no socket implementation. Its transport trait receives the policy-selected HTTPS origin and credentials only at the isolated host boundary. Request/response bodies can contain personal and account data and must not be logged.

## Supported flow

The adapter models the documented v2 transfer sequence:

1. Discover payers with `GET /payers`. Payer requirements are data-driven and can change additively; callers must use the returned payer requirements rather than hard-coding Tanzania or another corridor's beneficiary fields.
2. Optionally call Credit Party Information or Credit Party Verification for the selected payer and transaction type.
3. Create a quotation with a deterministic `acq_...` external ID derived from `PaymentQuoteId`.
4. Create the transaction from that quotation with a deterministic `act_...` external ID derived from `PaymentAttemptId`.
5. Confirm the transaction.
6. Retrieve the transaction by `external_id` until a terminal provider status is observed.

The deterministic IDs are domain separated and stay below Thunes' 64-character external-ID limit. They are the recovery and idempotency anchor and must not be replaced by caller-selected identifiers.

## Money handling

Provider monetary values are parsed as decimal text/JSON numbers into integer atomic units. The connector never converts transfer amounts through binary floating point. The authenticated transaction response must match the expected source currency and exact atomic amount before a `ProviderObservationV1` can be produced.

For a Tanzania deployment, TZS precision, payer increments, minimums, maximums, supported transaction types, mobile-wallet/bank identifiers, and all required sender/beneficiary fields must come from current Thunes payer discovery for the contracted account. They are operational configuration, not protocol constants.

## Status normalization

Thunes v2 documents status classes 1 through 9. ActiveBridge maps them conservatively:

- 1 CREATED, 2 CONFIRMED, 5 SUBMITTED, 6 AVAILABLE -> `Pending`
- 3 REJECTED, 9 DECLINED -> `Rejected`
- 4 CANCELLED -> `Cancelled`
- 7 COMPLETED -> `Succeeded`
- 8 REVERSED -> `Reversed`
- any future/unknown class -> `Unknown`

This intentionally maps by status class rather than enumerating every detailed status code because Thunes documents new detailed statuses within an existing class as a non-breaking change. A class value outside the documented set fails safely to `Unknown`.

`COMPLETED` means Thunes reports payout completion. It is external evidence only. The connector emits `EvidenceClass::ConnectorAuthenticated`; only the independent ActiveChain settlement/finality path may create `ActiveChainFinalized` evidence.

## Callback rule

The public Money Transfer v2 documentation specifies callback delivery and retries but does not define a callback cryptographic signature. Consequently, this connector treats callback JSON only as a wake-up hint. It may be parsed to identify the transaction, but it must never create trusted provider evidence directly. The host must perform an authenticated `GET /transactions/ext-{external_id}` and normalize that response instead.

If the contracted Thunes environment supplies an additional authenticated callback mechanism, add it as a separately reviewed boundary rather than silently upgrading unsigned callbacks.

## Ambiguous dispatch recovery

Network failure after an HTTP request is dangerous because the connector may not know whether Thunes accepted it. `ThunesRecoveryState` therefore enforces write-before-effect recovery:

- persist `CreateInFlight` before creating the transaction;
- if the create response is lost, persist `CreateAmbiguous` and only retrieve by deterministic external ID;
- never blindly issue a second create from the ambiguous state;
- persist `ConfirmInFlight` before confirmation;
- if confirmation is ambiguous, retrieve by external ID and infer whether confirmation advanced;
- once confirmed, poll by external ID until a terminal provider status is obtained.

The host must persist each phase before the provider effect. A restart must resume from the persisted action, not from an application request replay.

## Pre-production Tanzania pilot gate

Before sending real funds in Tanzania, require all of the following evidence on the exact connector revision:

- Thunes pre-production credentials stored only through the configured secret manager/opaque handle;
- exact pre-production origin allow-listed in connector-host policy;
- discovery snapshot for every Tanzania payer/currency/service intended for the pilot;
- CPI/CPV exercised wherever the selected payer exposes it;
- exact quotation amount/fee/FX parsing tests against captured, redacted provider fixtures;
- CREATED -> CONFIRMED -> SUBMITTED -> COMPLETED simulation;
- representative REJECTED, DECLINED, CANCELLED, and REVERSED simulations where Thunes permits them;
- ambiguous create and confirm fault injection proving lookup-only recovery;
- duplicate external-ID handling and restart recovery;
- callback spoof/replay proving callbacks cannot create authenticated evidence;
- reconciliation between Thunes transaction history, ActiveBridge provider observations, and any later ActiveChain settlement transaction;
- operator incident procedure for unavailable payer, insufficient prefunding, API credential rotation, and manual reconciliation.

Production remains blocked until the external-rail pilot, legal/compliance requirements, funding/treasury controls, and independent security review applicable to the deployment are complete.
