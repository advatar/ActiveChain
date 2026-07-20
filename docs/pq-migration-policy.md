# Post-quantum suite policy

ActiveChain launches with post-quantum consensus, transport authentication,
and protected-envelope boundaries from genesis. There is no classical fallback
window in the testnet profile.

## Admission rules

- Validator consensus signatures must use ML-DSA-44 and the exact registered
  key/signature sizes.
- A classical or partially registered `CryptoSuiteId` is rejected by every
  safety-critical constructor (`require_post_quantum`) before bytes reach an
  engine or verifier.
- Peer handshakes and authenticated consensus envelopes use ML-DSA-44 only.
- Protected transaction envelopes use ML-KEM-768 for key establishment; a
  classical confidentiality dependency is not an acceptable fallback.

## Future suite changes

Every future suite is introduced as a canonical `CryptoMigrationWindow` with:

1. a post-quantum registered suite,
2. an explicit activation height, and
3. an optional deprecation height strictly after activation.

The suite is active only on the half-open interval
`activation_height <= height < deprecation_height`. A migration cannot be
accepted without deterministic vectors, malformed-input rejection tests, and a
local-runner rehearsal before a live testnet upgrade.

## Key-class matrix

| Key class | Day-one suite | Migration requirement |
| --- | --- | --- |
| Validator consensus | ML-DSA-44 | Finalized epoch transition and bounded migration vector |
| Principal / credential signatures | Registered PQ signature suite | Purpose-specific validation and activation window |
| Transport peer identity | ML-DSA-44 | Authenticated reconnect handshake before frame admission |
| Protected-envelope key establishment | ML-KEM-768 | New envelope domain/version and decapsulation vectors |
| ObjectVM execution evidence | ML-DSA-44 evidence signatures | Replay-verification vector before activation |

No class may silently fall back to a classical key. An unrecognized class,
suite, or window is rejected as a configuration error and cannot enter a
consensus-critical state transition.
