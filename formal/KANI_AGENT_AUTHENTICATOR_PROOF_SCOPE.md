# Kani agent-authenticator proof scope

Two Kani harnesses execute the exact production rotation-admission helper in
`activechain-wallet-core`.

They prove for arbitrary revisions, history lengths, heights, and lifecycle flags that:

1. every accepted rotation satisfies all capacity, revision, activity, height, and overflow gates
   and produces a strictly greater revision; and
2. compromised or deactivated agents cannot pass rotation admission.

The proofs do not cover ML-DSA security, authenticator/device attestation provenance, secure
hardware, filesystem crash semantics, SHAKE256 collision resistance, enrollment-channel
authentication, finalized principal lifecycle authorization, or synchronization across devices.
Runtime tests cover canonical structure, duplicate authenticator rejection, stale rotation,
no-resurrection behavior, snapshot restart, and checksum corruption.

Run with Kani 0.67 after applying the repository-documented temporary Rust-version metadata
compatibility workaround required because the workspace MSRV is newer than the Rust embedded by
that Kani release:

```bash
cargo kani -p activechain-wallet-core \
  --harness accepted_rotation_strictly_increments_revision_and_respects_every_gate \
  --harness compromised_or_deactivated_agent_cannot_rotate
```
