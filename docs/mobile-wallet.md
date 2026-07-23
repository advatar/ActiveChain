# ActiveChain mobile wallet plan

The mobile wallet is a thin native shell over `activechain-wallet-core`. Cryptographic and Coin Cell
logic MUST remain in the shared Rust core; Swift/Kotlin code owns platform UI, lifecycle, secure
storage handles, and transport.

## Native boundary

The first bridge exposes a small versioned API:

- derive or import a wallet profile;
- list public key/DID metadata;
- request Coin Cell discovery;
- evaluate a spending policy;
- construct a canonical transfer intent;
- sign only an approved intent;
- export an encrypted backup envelope;
- rotate or recover a key slot.

No bridge function accepts an unconstrained amount/recipient pair, returns plaintext secret keys,
or performs network calls while holding decrypted key material longer than necessary.

The current Rust bridge is `activechain_wallet_core::WalletBridge`; native shells bind to its
policy-gated `approve_and_build` operation and pass only opaque `KeySlot` ciphertext handles.

Wallet ABI revision 1 now exposes `activechain_wallet_select_cells`. Native callers pass a
canonical bounded `CoinCellSet`, owner, amount, and fee as two-word unsigned values; the core
returns distinct deterministic payment and fee-reserve identifiers. Null, oversized, malformed,
wrong-owner, and insufficient-funds inputs fail without publishing output state.

## iOS and Android

- iOS stores encrypted key-slot material behind Keychain/Secure Enclave handles.
- Android stores encrypted key-slot material behind Android Keystore handles.
- The Rust core receives opaque ciphertext or hardware-backed signing callbacks.
- UI displays the exact recipient, amount, fee reserve, validity height, and policy decision before
  approval.

## Interoperability adapters

OpenWallet credential/application adapters and EUDI Wallet OpenID4VCI/OpenID4VP integration stay
outside the transaction kernel. ENS names are display/discovery aliases, never signing authority.

## Release sequence

1. Testnet CLI and transaction ingress.
2. Rust FFI contract and golden vectors.
3. iOS/Android shell prototypes against a local three-validator network.
4. Secure-storage and recovery audit, as part of the external pre-launch review in
   `docs/SECURITY_AUDIT.md` (independent firm with PQ and mobile expertise; no audit has been
   completed yet).
5. Public mobile beta after testnet replay/restart/finality rehearsals pass.
