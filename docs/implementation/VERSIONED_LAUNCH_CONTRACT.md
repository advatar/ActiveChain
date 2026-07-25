# Versioned launch contract

This contract sequences the complete ActiveChain thesis; it does not remove features. A later
milestone changes when a feature becomes mandatory, never the meaning of bytes already accepted.

| Release | Mandatory qualification gate | Explicit boundary |
| --- | --- | --- |
| v1.0 | PQ authorization, object state, cash lane, reserved proof/header seams, deterministic validator re-execution | No proof-carrying validity claim; re-execution is authoritative |
| v1.1 | Proof-carrying validity, PQ-ZK profile, light-client verification, prover fallback/liveness policy | The public validity/ordering separation claim begins here |
| v1.2 | Shielded payments, protected ordering, multidimensional fees/state rent, compute assurance tiers | Each feature activates only under its versioned profile |

## Genesis reservation requirements

The v1.0 codec reserves type-tag ranges for shielded notes, proof statements, compute jobs,
protected-ordering envelopes, fee dimensions, and light-client checkpoints. Block headers reserve
the proof commitment, verifier revision, feature bitmap, and extension commitment fields. Envelope
dispatch is versioned and length-delimited so unknown extensions can be rejected without parsing
or reinterpreting their payload.

Every future activation has a distinct protocol revision and activation rule. A v1.0 client must
reject an unknown active tag, unsupported feature bit, malformed extension length, or proof profile;
it must never ignore these fields and continue as if the feature were absent.

This preserves the core thesis while making the launch sequence honest: v1.0 is a development
network whose validity authority is validator re-execution; v1.1 is the first release eligible
to claim proof-carrying validity after its independent qualification gates pass.
