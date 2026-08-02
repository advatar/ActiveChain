# ActiveBridge Rust SDK v1

`activechain-payment-sdk` is the transport-neutral client boundary for ActiveBridge. HTTP, RPC,
and embedded adapters implement `ActiveBridgeTransport`; the SDK itself performs no ambient
network access and does not treat a provider response as ActiveChain finality.

Each `PaymentSdkRequestV1` contains a bounded opaque operation body and a canonical
`PaymentApiSignedAuthorizationV1`. Construction requires the authorization's request commitment
to open the exact body bytes. The signed authorization separately binds caller, audience,
operation, idempotency identity, optional payment intent, sequence, validity, and authenticator.

Each `PaymentSdkResponseV1` binds the complete request commitment. Rejected responses cannot carry
lifecycle or proof material. A `Finalized` or `Refunded` lifecycle requires non-empty proof bytes,
but presence is not verification. Production callers use `execute_verified` and provide the
trusted-genesis finality/receipt verifier for the supported proof profile; rejection by that
verifier returns `ProofRejected` and no finalized result.

Transport adapters must preserve the canonical envelope bytes, impose their own response-size and
deadline limits, authenticate the remote endpoint, and avoid logging body, authorization, or proof
bytes. Idempotent replay remains explicit in `PaymentSdkOutcome` and is accepted only when the
response correlates to the exact original request commitment.
