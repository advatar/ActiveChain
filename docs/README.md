# ActiveChain documentation

This index routes readers to the right source of truth. Documents have different authority:

1. versioned specifications under [`spec/protocol/`](../spec/protocol/) define intended protocol
   requirements;
2. canonical schemas and deterministic vectors define encoding/conformance evidence;
3. implementation documents explain current code boundaries;
4. operational and audit documents record procedures and evidence;
5. [`STATUS.md`](../STATUS.md) tracks delivery but does not override specifications.

All surfaces remain developmental unless a document explicitly establishes a narrower qualified
claim. No independent security audit has been completed.

## Start here

- [Repository README](../README.md) — project overview and quick start
- [Architecture guide](ARCHITECTURE_GUIDE.md) — cross-cutting system model
- [Implementation status](../STATUS.md) — current roadmap and linked issues
- [System goals](../spec/protocol/P-000-system-goals.md) — normative design goals
- [Protocol specification directory](../spec/protocol/) — versioned protocol drafts
- [Formal verification guide](../formal/README.md) — models, scope, and checks

## Protocol and compatibility

- [Protocol version series](PROTOCOL_VERSION_SERIES_V1.md)
- [Conformance surface](CONFORMANCE_SURFACE_V1.md)
- [Independent-client contract](DBROWSER_DOWNSTREAM_CONTRACT_V1.md)
- [Distribution compatibility](DISTRIBUTION_COMPATIBILITY_V1.md)
- [Proof liveness](PROOF_LIVENESS_V1.md)
- [Validator economics](VALIDATOR_ECONOMICS_V1.md)

Canonical protocol drafts for encoding, cryptography, principals, credentials, capabilities,
policies, objects, state, actions, ObjectVM, proofs, storage, payments, identity, compliance, and
economics are numbered under [`spec/protocol/`](../spec/protocol/).

## Identity, credentials, and wallets

- [VCIssuer integration](VCISSUER_INTEGRATION_V1.md)
- [Identity interoperability qualification](identity/INTEROPERABILITY-QUALIFICATION.md)
- [EUDI TLSNotary/ZK boundary](EUDI_TLSN_ZK_BOUNDARY_V1.md)
- [Mobile wallet architecture](mobile-wallet.md)
- [Wallet agent management](wallet-agent-management.md)
- [Post-quantum migration policy](pq-migration-policy.md)
- [Native wallet documentation](../mobile/README.md)

## Payments, assets, and external settlement

- [ActiveBridge v1](ACTIVE_BRIDGE_V1.md)
- [ActiveBridge operations drill](ACTIVEBRIDGE_OPERATIONS_DRILL_V1.md)
- [Native asset RPC](NATIVE_ASSET_RPC_V1.md)
- [Faucet ingress](FAUCET_INGRESS_V1.md)
- [Faucet funding admission](FAUCET_FUNDING_ADMISSION_V2.md)
- [PQ-ZK cash proof boundary](PQ_ZK_CASH_PROOF_BOUNDARY_V1.md)

## Proofs and implementation notes

- [ActiveChain PQ-ZK v1](implementation/activechain-pq-zk-v1.md)
- [CashAIR SHAKE](implementation/cash-air-shake.md)
- [CashAIR ML-DSA NTT tables](implementation/cash-air-mldsa-ntt.md)
- [Authenticated cash partitions](implementation/authenticated-cash-partitions.md)
- [Authoritative cash sessions](implementation/authoritative-cash-sessions.md)
- [Verifier SDK](implementation/verifier-sdk.md)
- [External digest anchoring](implementation/external-digest-anchoring.md)

The [`implementation/`](implementation/) directory contains additional bounded implementation
contracts. These describe code as implemented; they are not automatically normative.

## Agents and applications

- [Agent interfaces](AGENT_INTERFACES_V1.md)
- [Agent interface qualification](AGENT_INTERFACE_QUALIFICATION_V1.md)
- [MCP read-only profile](MCP_READ_ONLY_V1.md)
- [MCP proposal gateway](MCP_PROPOSAL_GATEWAY_V1.md)
- [MCP transfer rehearsal](MCP_TRANSFER_REHEARSAL_V1.md)
- [A2UI renderer](A2UI_RENDERER_V1.md)
- [Compute-job boundary](COMPUTE_JOB_BOUNDARY_V1.md)
- [Private billboard specification](specifications/private-billboard-emerald-ambition.md)

## Operations, releases, and security

- [Testnet release boundary](TESTNET_RELEASE.md)
- [Testnet release gate](TESTNET_RELEASE_GATE_V1.md)
- [Testnet operations](testnet-operations.md)
- [Release assurance evidence](RELEASE_ASSURANCE_EVIDENCE_V1.md)
- [Security audit requirement](SECURITY_AUDIT.md)
- [Security audit scope](SECURITY_AUDIT_SCOPE.md)
- [Self-hosted CI runner](ci/self-hosted-runner.md)

Security vulnerabilities must be reported according to [`SECURITY.md`](../SECURITY.md), not in a
public issue.

## Compliance profiles

The [`compliance/`](compliance/) directory contains versioned profile semantics, evidence controls,
privacy boundaries, jurisdiction matrices, and change logs. These are technical protocol profiles,
not legal advice or certification of regulatory compliance.

## Documentation changes

Follow [`CONTRIBUTING.md`](../CONTRIBUTING.md). New major document families should be linked here,
state their authority and maturity, and avoid claims broader than their executable or reviewed
evidence.
