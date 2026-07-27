# Native asset RPC contract v1

Native asset queries use the existing bounded `Get`/`List` proof envelope and distinguish asset
classes explicitly. A proof-bearing response includes the finalized height, chain/genesis identity,
record commitment, and the proof kind named by `RpcStatus`.

Required query families:

- asset definition and immutable policy;
- issuer registration and approval commitments;
- current supply and supply-attestation;
- owner-scoped fungible Coin Cells;
- NFT token/series ownership records;
- lifecycle action and settlement receipt;
- attestation/status evidence commitments.

Verification binds every response to AssetId, owner (when scoped), action/receipt ID, policy
revision, finalized block and root. Unsupported proof kinds return a typed error. An empty result
is not a zero balance and must not be used to synthesize wallet state.
