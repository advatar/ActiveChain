# Ordered protocol-version series

ActiveChain versions are additive protocol profiles. A later version may activate reserved
fields and tags, but may not reinterpret bytes accepted by an earlier version.

| Version | Mandatory surface | Deferred surface | Activation gate |
|---|---|---|---|
| v1.0 | canonical envelopes, PQ consensus, validator re-execution, native cash, bounded RPC | validity proofs, shielded transfers, NFT authenticated tree | genesis qualification |
| v1.1 | v1.0 plus proof-carrying validity and light-client checkpoints | shielded transfer execution | governed upgrade at exact height |
| v1.2 | v1.1 plus shielded transfer execution and privacy proofs | future application extensions | governed upgrade at exact height |

Each version must publish its protocol revision, verifier revision, supported proof set, reserved
type-tag ranges, header fields, envelope extension points, and negative vectors. An older client
must reject an unknown tag or extension; it must not ignore it and continue with a different
meaning.

Upgrade authorization binds the exact next revision, activation height, parent finalized block,
new genesis/validator context where applicable, and a rollback or halt policy. Activation is
atomic: a node either uses the complete new profile at the declared height or remains on the
previous profile without advancing finality.
