# Thunes ActiveBridge connector plan

Status: implementation branch claim

This work adds Thunes Money Transfer API v2 as an out-of-consensus ActiveBridge rail implementation. The connector must preserve P-091 boundaries: provider-specific JSON and credentials remain outside validators, external provider success never implies ActiveChain finality, exact request/response commitments bind observations, and provider operations are recoverable through durable idempotency.

Planned scope:

- Thunes connector configuration with sandbox/production HTTPS origin allow-listing and secret-handle based credentials.
- Provider-neutral request transport boundary; no Thunes credentials in canonical values or source.
- Payer discovery and beneficiary CPI/CPV request support.
- Quotation creation and exact translation inputs for `PaymentQuoteV1`.
- Transaction creation, confirmation, polling by provider/external ID, and callback normalization.
- ActiveChain attempt/quote identifiers mapped to deterministic Thunes `external_id` values.
- Strict status-class mapping to `ProviderOperationState`; Thunes completion produces external evidence only.
- Durable journal integration and reconciliation hooks.
- Unit/contract tests using a deterministic mock transport; no live credentials required.
- Operator documentation for sandbox credentials, callback handling, and secret storage.

Qualification:

- `cargo fmt --check`
- affected-crate `cargo check`, tests, and Clippy
- complete deterministic-kernel gate before merge
