# Faucet funding admission v2

Status: testnet-only implementation contract. This is not a production issuance path.

The wallet first fetches `FaucetTermsV1`, constructs `FaucetRequestV1`, and derives its settlement
reference from the complete canonical request under `ACTIVECHAIN-TESTNET-FAUCET-REFERENCE-V2`.
Unlike the former server-only reference, this value contains no server-derived peer identity, so
the wallet can derive and track it before submission. Peer identity remains private, off-chain
rate-limit state and is never accepted from the request.

The public wallet submits only `RequestFaucet(FaucetRequestV1)`. It never receives or signs with
the faucet treasury key. After policy admission, an operator/HSM authorizer builds
`CashAuthorizationRequestV1` schema 2 with
`settlement_reference = Some(request.settlement_reference())` and signs the complete canonical
payload with the treasury's ML-DSA-44 cash key. `AuthorizedFaucetRequestV1` remains an
operator/internal bridge shape; requiring a public client to supply it would disclose or misuse
treasury signing authority and is not a deployable wallet flow.

Admission is ordered and fail-closed:

1. RPC framing and faucet policy validate the chain, genesis, challenge, limits, and idempotency.
2. The durable faucet reserves the exact request before invoking operator authorization.
3. `DurableOperatorFaucetSettlement` persists the byte-exact signed envelope before ingress, so a
   retry after a lost acknowledgement replays the same transaction rather than signing a new spend.
4. Validator ingress decodes and cryptographically verifies the signed cash request.
5. The signed settlement reference, recipient, configured amount, chain, nonce, session, inputs,
   and validity height must all match.
6. The one-shot operator session, cash state, and replay barriers persist atomically before a
   transaction identifier is returned.
7. Wallet balance remains unchanged until owner-scoped Coin Cells are published with exact
   finalized-block evidence through the fail-closed Kanalen path.

Reference, recipient, amount, chain, envelope, or height substitution rejects without consuming
cash authorization state. Retrying the same exact admitted transaction is idempotent. Schema-1
cash authorizations are rejected at the network boundary; there is no pre-testnet migration need.

The current implementation provides the fail-closed native funding lifecycle presentation, but
does not enable its action until the platform cash-key adapter and public operator signer are
installed. The complete journal/filesystem refinement proof also remains a launch task in
`STATUS.md`.

## Operator configuration

An enabled `activechain-rpc-node` faucet additionally requires:

- `ACTIVECHAIN_WALLET_INGRESS_SNAPSHOT`: initialized cash ingress containing the treasury's
  finalized authorization lane and at least two treasury-owned Coin Cells;
- `ACTIVECHAIN_FAUCET_OPERATOR_SEED`: a regular file containing exactly 32 binary seed bytes,
  with no group or world permission bits;
- `ACTIVECHAIN_FAUCET_SOURCE`: the treasury principal as 96 lowercase hexadecimal characters;
- `ACTIVECHAIN_FAUCET_SETTLEMENT_JOURNAL`: the separately durable prepared-envelope journal;
- `ACTIVECHAIN_FAUCET_FEE` and `ACTIVECHAIN_FAUCET_VALIDITY_BLOCKS`: bounded transfer policy.

The seed is read into a fixed-size value, the input buffer is zeroized, symlinks and permissive
files are rejected, and no arbitrary network payload reaches the signer. Production custody should
replace the seed-file loader with an HSM/secure-service implementation of
`FaucetEnvelopeAuthorizer`; the file loader is acceptable only for the developmental testnet.
