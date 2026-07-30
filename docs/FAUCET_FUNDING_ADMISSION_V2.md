# Faucet funding admission v2

Status: testnet-only implementation contract. This is not a production issuance path.

The wallet first fetches `FaucetTermsV1`, constructs `FaucetRequestV1`, and derives its settlement
reference from the complete canonical request under `ACTIVECHAIN-TESTNET-FAUCET-REFERENCE-V2`.
Unlike the former server-only reference, this value contains no server-derived peer identity, so
the wallet can bind it before signing. Peer identity remains private, off-chain rate-limit state
and is never accepted from the request.

The wallet then builds `CashAuthorizationRequestV1` schema 2 with
`settlement_reference = Some(request.settlement_reference())`, signs the complete canonical
payload with ML-DSA-44, and submits both values in `AuthorizedFaucetRequestV1`.

Admission is ordered and fail-closed:

1. RPC framing and faucet policy validate the chain, genesis, challenge, limits, and idempotency.
2. The durable faucet reserves the exact request and settlement-envelope commitment before ingress.
3. Validator ingress decodes and cryptographically verifies the signed cash request.
4. The signed settlement reference, recipient, configured amount, chain, nonce, session, inputs,
   and validity height must all match.
5. Cash state and replay barriers persist atomically before a transaction identifier is returned.
6. Wallet balance remains unchanged until owner-scoped Coin Cells are published with exact
   finalized-block evidence through the fail-closed Kanalen path.

Reference, recipient, amount, chain, envelope, or height substitution rejects without consuming
cash authorization state. Retrying the same exact admitted transaction is idempotent. Schema-1
cash authorizations are rejected at the network boundary; there is no pre-testnet migration need.

The current implementation does not yet provide the native Apple funding UI or the complete formal
faucet refinement proof. Those remain launch tasks in `STATUS.md`.
