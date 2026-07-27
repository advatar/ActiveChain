# Wallet multi-asset ABI v1

Every wallet balance, selected input, output, fee quote, approval, signature, and submission
envelope carries the canonical `AssetId`. Symbols, decimals, and display names are metadata only.

Selection is performed over finalized owner-scoped Coin Cell proofs filtered by `(chain_id,
asset_id, owner)`. A fee policy names its fee asset explicitly; wallets must not silently convert
or spend another asset to pay fees. The approval screen displays the immutable asset identifier,
issuer, amount, decimals, policy profile, and proof height before signing.

The ABI returns structured unavailable/expired/revoked states instead of zero balances. A client
that does not understand an asset or profile must reject the intent before signing, while older
clients reject the versioned envelope rather than reinterpret it as native currency.
