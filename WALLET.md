Build a small ActiveChain wallet POC first. Do not fork MetaMask, Rabby, Trust Wallet, or another EVM wallet.

  The reason is structural: ActiveChain is not EVM-compatible and its wallet model is fundamentally different:

  - ML-DSA authorization instead of secp256k1/Ed25519
  - ML-KEM sessions
  - Coin Cell selection instead of account-balance transactions
  - explicit fee reserves
  - DID Documents and capability delegation
  - shielded/private intents and witnesses
  - agent spending policies
  - recovery and key rotation as protocol operations

  A conventional wallet fork would give us a familiar UI but inherit the wrong cryptographic assumptions, transaction model, and account abstraction.

  ## Recommended approach

  Build an activechain-wallet-core first, then put multiple frontends on top.

  activechain-wallet-core
    ├─ PQ key generation and encrypted keystore
    ├─ DID and principal management
    ├─ Coin Cell discovery and selection
    ├─ fee estimation and fee-reserve construction
    ├─ transaction construction and signing
    ├─ capability and spending-policy enforcement
    ├─ reward/bond/challenge operations
    ├─ encrypted backup and recovery
    └─ RPC/client interface

  activechain-wallet-cli
    ├─ create wallet
    ├─ derive DID
    ├─ inspect balance and Coin Cells
    ├─ send
    ├─ bond as verifier
    ├─ submit duty receipt
    └─ redeem rewards

  later:
    ├─ desktop wallet
    ├─ mobile wallet
    ├─ browser integration
    └─ hardware-wallet support

  The first POC should be a CLI, not a polished mobile app. It will let us validate:

  1. PQ key generation and storage.
  2. Principal/DID derivation.
  3. Coin Cell selection.
  4. Explicit fee reserves.
  5. Signed transfer creation.
  6. Testnet submission.
  7. Deterministic recovery.
  8. Verifier bond and reward flows.

  The wallet must never expose raw private keys to applications or agents. Agent access should be policy-gated: an agent receives a scoped capability such as “spend up to 10 ACT per
  day with these recipients,” rather than unrestricted signing authority.

  ## What to reuse

  Reuse standards and libraries at the edges, not another chain’s wallet core.

  - The Wallet Standard provides common wallet/application interfaces and registration conventions for ecosystem integration. Wallet Standard
    (https://wallet-standard.github.io/wallet-standard/)

  - WalletConnect can be considered later for application-to-wallet sessions, but its transaction model should wrap ActiveChain intents rather than pretend ActiveChain is Ethereum.
    WalletConnect SDK (https://docs.walletconnect.network/app-sdk/overview)

  - OpenWallet Foundation components are relevant for credential interoperability and wallet architecture. Their architecture explicitly separates money, identity, objects, storage,
    policy, and communication layers. OpenWallet architecture (https://github.com/openwallet-foundation/architecture-sig/blob/main/docs/papers/architecture-whitepaper.md)

  - EUDI Wallet interoperability should be handled by a credential adapter, not by making our native coin wallet responsible for EU identity compliance.

  ## Key-management design

  The POC should support:

  - ML-DSA-65 signing keys
  - ML-KEM-768 agreement keys
  - optional SLH-DSA recovery keys
  - encrypted local keystore
  - passphrase-based unlock
  - key versioning and rotation
  - explicit recovery policy
  - offline backup export
  - zero plaintext key logging
  - deterministic test vectors

  We should avoid inventing a mnemonic scheme until the PQ key-derivation and backup format are frozen. A seed phrase designed for small elliptic-curve keys is not automatically
  suitable for ML-DSA key material.

  ## Important product decision

  The first wallet should be called an ActiveChain Wallet, but architecturally it should be a universal identity, capability, and money wallet:

  - native ACT balance
  - Coin Cells
  - verifier bonds
  - reward claims
  - DIDs
  - credentials
  - capabilities
  - agent policies
  - private transaction sessions

  That matches the OpenWallet Foundation’s multi-purpose wallet model rather than treating the product as a coin-only wallet. OpenWallet Foundation
  (https://openwallet.foundation/projects/)

  My recommendation is therefore:

  > Build the POC wallet in-house, make the core Rust and protocol-owned, expose a clean TypeScript/CLI interface, and add external wallet standards only as adapters after the
  > ActiveChain transaction and identity semantics are stable.

  This gives us a usable testnet wallet quickly without importing cryptographic or accounting assumptions that ActiveChain was designed to eliminate.
