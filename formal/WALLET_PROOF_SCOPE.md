# Wallet-agent Tamarin proof scope

`formal/tamarin/activechain_wallet.spthy` models the authorization boundary between an owner,
a delegated agent, a canonical intent, a trusted local biometric service, and one-shot ledger
acceptance.

Verified safety properties:

- every accepted intent has a prior owner/agent-bound approval;
- every approval has a prior trusted biometric authentication for the same owner;
- one biometric grant authorizes at most one approval;
- one canonical intent identifier is accepted at most once.

The biometric service is an explicit trusted-platform assumption. The model treats a successful
Face ID/Secure Enclave callback as a fresh linear grant; it does not prove Apple's implementation,
sensor security, UI integrity, or resistance after operating-system compromise. The native wallet
must request biometric-only policy, fail closed on lockout/error, and never turn a passcode fallback
into the same grant.

The theory abstracts cryptographic primitives symbolically and does not yet model amounts,
fee arithmetic, network finality, FFI memory safety, malware, side channels, denial of service, or
key recovery. Those properties require their own models and implementation mapping.
