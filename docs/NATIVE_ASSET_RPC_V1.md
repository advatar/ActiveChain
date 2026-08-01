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

The implemented finalized-state families use `AssetDefinition`, `AssetIssuerRegistration`,
`AssetSupplyAttestation`, `AssetCorporateAction`, and `AssetSettlementReceipt` query kinds. Their
values are canonical state `Object` envelopes whose public value must decode as the exact named
native asset type. The object `type_id` commits to the query kind and canonical type tag, its
`value_root` commits to the exact public-value bytes, and its sparse state proof must verify against
the finalized header's `post_state`. Supply attestations and settlement receipts additionally bind
their own finalized height to the record height. A caller cannot relabel one asset record family as
another or substitute metadata while retaining a valid proof.
