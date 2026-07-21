# ActiveChain pre-launch security audit

## Status

**No security audit has been completed.** In ActiveChain documents, "audit" means this required
pre-launch review — it is not an existing or in-progress engagement. Until the audit described here
is completed, published, and re-reviewed, the wallet, the verifier packages, and every testnet are
explicitly **developmental**: they carry no security assurances and MUST NOT hold value anyone is
unwilling to lose.

## Auditor requirements

The audit MUST be performed by an independent external blockchain/security firm (or coordinated
group of specialist firms) with demonstrated expertise in:

- post-quantum cryptography (ML-DSA, ML-KEM, SLH-DSA, SHAKE-based constructions);
- Rust consensus and ledger kernels;
- C ABI/FFI review and native mobile wallet security (iOS and Android).

The engagement is independent: the firm has no financial stake in ActiveChain, reports findings
directly, and controls its own methodology. Internal review, CI, property tests, and the Lean
models are audit *inputs*, not substitutes.

## Scope

The audit covers six areas. Each maps to concrete code and specifications in this repository.

### 1. Rust consensus, cash economics, replay protection, and state transitions

- `crates/devnet-kernel`, `node/semantic-devnet` — deterministic block application and host shell.
- `crates/action-kernel` — action envelopes, nonce channels, fee tickets, replay/gap rejection.
- `crates/cash-kernel` — native Coin Cell money, genesis allocation, issuance, burn, supply
  accounting, verifier bonds/duties/challenges, fee quotes.
- `crates/transition`, `crates/object`, `crates/state-tree` — atomic transfers, object ownership,
  sparse state commitments and witnesses.
- `crates/consensus-runtime`, `crates/data-availability` — consensus and DA components.
- Specifications under `spec/protocol/`; economics in `CASH.md`, `MINT.md`, `REWARDS.md`.
- Key questions: value conservation, no double spend or double mint, replay protection across
  restart/reorg, determinism of receipts and post-state roots, safety of the issuance schedule.

### 2. Post-quantum cryptography and ML-DSA/ML-KEM usage

- `crates/crypto-provider`, `crates/protocol-commitment` — PQ suites, SHAKE256/384 domain-separated
  commitments.
- `crates/protocol-types`, `crates/principal`, `crates/credential` — authenticators, key lifecycle,
  rotation, recovery.
- `docs/pq-migration-policy.md` and the DID method draft `spec/protocol/P-095`.
- Key questions: correct parameter sets and encodings, domain-separation completeness, nonce and
  randomness handling, key lifecycle (rotation, recovery, revocation), downgrade and suite-confusion
  resistance, side-channel exposure of signing paths.

### 3. C ABI/FFI memory safety and native wallet integration

- `crates/wallet-ffi`, `crates/verifier-ffi` — the versioned C ABI surfaces.
- `crates/wallet-core` (`WalletBridge`, `approve_and_build`, opaque `KeySlot` handles).
- Key questions: pointer/length contract soundness, lifetime and ownership across the boundary,
  panic and unwind safety, versioning/ABI-evolution safety, zeroization of secret material, absence
  of plaintext-key returns, robustness against malformed inputs from the native side.

### 4. iOS Keychain/Secure Enclave and Android Keystore handling

- `mobile/ios/ActiveChainWallet`, `mobile/ios/ActiveChainWalletApp`,
  `mobile/android/ActiveChainWallet` — the native shells.
- The shared-core/native-shell boundary frozen in `docs/mobile-wallet.md`.
- Key questions: key-slot ciphertext handling, Keychain/Secure Enclave and Keystore attribute
  correctness (access control, biometry binding, backup exclusion), hardware-backed signing
  callback integrity, encrypted backup envelope security, recovery flows, and that the UI shown at
  approval exactly matches the signed intent.

### 5. OpenWallet interoperability and protocol conformance

- The OpenWallet credential/application-session adapter boundary in `crates/wallet-core`.
- EUDI Wallet OpenID4VCI/OpenID4VP and mdoc/VC presentation plans (`docs/mobile-wallet.md`,
  DID method `P-095`).
- Key questions: adapter isolation from the transaction kernel, conformance with the relevant
  OpenWallet/OpenID4VC profiles, credential presentation replay and cross-protocol confusion,
  and that no interoperability path can authorize spending outside the policy-gated intent flow.

### 6. Threat modeling, fuzzing, property tests, and validator/network abuse

- A whole-system threat model covering wallets, ingress, validators, the verifier economy, and the
  DA layer.
- Review and extension of existing property tests and `testing/vectors/` fixtures; targeted fuzzing
  of the canonical codec (`crates/canonical-codec`), bytecode verifier
  (`crates/bytecode-verifier`), ObjectVM (`crates/object-vm`), envelope parsing, and both FFI
  surfaces.
- Validator/network abuse: eclipse and partition behavior, ingress flooding, fee-market
  manipulation, verifier-duty and challenge gaming, slashing-evasion and reward-inflation paths.

## Artifacts available to auditors

- Normative protocol drafts under `spec/protocol/` and the canonical schema `schema/activechain.idl`.
- Executable Lean models and proofs under `formal/lean/` with Rust differential fixtures.
- Deterministic cross-implementation vectors under `testing/vectors/` with a machine-readable
  manifest and malformed/tampered fixtures.
- A reproducible CI matrix on the pinned Rust toolchain (`rust-toolchain.toml`), with all
  consensus-kernel crates `#![no_std]` and `#![forbid(unsafe_code)]`.

## Process and launch gate

1. **Engagement.** Select the firm(s) against the requirements above; freeze the audit commit.
2. **Audit.** The firm reports findings with severity ratings and reproduction steps.
3. **Remediation.** Every finding gets a fix or an explicitly accepted, documented risk.
4. **Re-review.** The firm re-reviews all fixes; regressions reopen the finding.
5. **Publication.** The final report and the remediation log are published in this repository.

Launch (any non-developmental release of the wallet, verifier packages, or a value-bearing
network) is **blocked** until steps 1–5 are complete. Testnets may run before then but MUST be
labeled developmental, and `docs/TESTNET_RELEASE.md` gates what a testnet may claim.
