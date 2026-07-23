# Embeddable light client

The `activechain-light-client` crate packages ActiveChain finality verification and durable trust
state behind a downstream-facing Rust API.

## Trust model

Bootstrap requires an application-selected chain identifier, immutable chain-genesis commitment,
and a cryptographically verified finalized checkpoint. The caller also selects a bounded
weak-subjectivity period. Updates fail closed once the observed network height exceeds that trust
window.

Every accepted header must:

- be exactly one height after the current checkpoint;
- name the current header digest as its parent;
- match the selected chain identifier and immutable chain genesis;
- carry a valid quorum certificate from the active validator set; and
- match the active epoch and protocol revision.

Validator-set and protocol changes require a quorum-authorized `UpgradeCertificateBundle`.
Activation is exact-height, and previously retired validator-set roots cannot be reactivated.

## Proofs and data availability

`LightClientState::verify_query` accepts the canonical proof-bearing RPC record and binds its
state, ordered action set, or receipt proof to the current finalized header. The verifier receives
the immutable chain-genesis commitment explicitly, so proofs continue to verify after validator
transitions.

`LightClientState::verify_data_availability` reconstructs and validates the bounded availability
batch before comparing its payload commitment with the current finalized header.

## Persistence

`PersistentLightClient` atomically replaces a canonical snapshot only after verification succeeds.
Snapshots include the checkpoint, active validator manifest, weak-subjectivity deadline, retired
validator roots, and any pending upgrade. A domain-separated integrity tag detects truncation or
corruption, while canonical decoding revalidates semantic invariants and pending upgrade
certificates before returning state to the caller.
