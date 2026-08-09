# Application payment verifier service v1

The application payment verifier is ActiveChain's reusable boundary for consumers that must admit
an operation only after an exact payment has finalized. It owns canonical decoding and finality
semantics; applications supply their expected request, audience, and policy bindings rather than
reimplementing ledger verification.

## Production verification

`POST /v1/verify-inference-authorization` accepts the versioned
`actum.payment-finality.v1` JSON transport contract. Its `payment_evidence_b64` field decodes to:

```json
{
  "payment_intent_b64": "<canonical PaymentIntentV1 envelope>",
  "finalized_settlement_b64": "<canonical PaymentFinalizedSettlementV1 envelope>",
  "finality_bundle_b64": "<canonical finality bundle>",
  "block_receipt_b64": "<canonical block receipt>"
}
```

The service verifies:

- the configured chain, genesis, and merchant;
- payment-intent validity and settlement amount bounds;
- the application's 48-byte request `Digest384` through `authorization_context`;
- the audience and token class through the intent metadata commitment;
- the finalized settlement, finality proof, block receipt, and exact transaction inclusion through
  `activechain-verifier-api`;
- the request replay identifier against the finalized transaction identifier.

The successful authorization identifier is the canonical payment-intent identifier. Callers must
use it as a durable one-use replay key. No evidence-supplied field is promoted to finality without
verification against the configured trusted genesis.

## Configuration

Required in every profile:

- `ACTIVECHAIN_PAYMENT_VERIFIER_BEARER_TOKEN` — at least 32 bytes;
- `ACTIVECHAIN_PAYMENT_VERIFIER_AUDIENCE` — exact application/merchant audience;
- `ACTIVECHAIN_PAYMENT_VERIFIER_LISTEN` — defaults to `127.0.0.1:8080`.

Production additionally requires three base64-encoded 48-byte values:

- `ACTIVECHAIN_TRUSTED_CHAIN_B64`;
- `ACTIVECHAIN_TRUSTED_GENESIS_B64`;
- `ACTIVECHAIN_PAYMENT_MERCHANT_B64`.

Place the service behind authenticated TLS. Health and readiness are exposed at `/healthz` and
`/readyz`. Authorization uses an exact bearer credential compared in constant time. Bodies and
decoded evidence are bounded before canonical decoding.

## Development fixtures

`ACTIVECHAIN_PAYMENT_VERIFIER_ALLOW_DEV_FIXTURES=true` activates a deterministic local integration
profile. It validates request, audience, token-class, replay, and response bindings but does not
verify ledger finality. The service emits a startup warning and reports
`local-development-only` from its health endpoint. This flag must never appear in production.

ZeroK uses this profile for its Docker-local encrypted paid-inference smoke test. Production ZeroK
uses the same endpoint contract with canonical evidence and the development flag absent.

## Container

Build from the ActiveChain repository root:

```sh
docker build -f deploy/payment-verifier/Dockerfile -t activechain-payment-verifier:local .
```
