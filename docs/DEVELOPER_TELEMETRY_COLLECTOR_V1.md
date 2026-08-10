# Actum developer telemetry collector v1

The `activechain-developer-telemetry` crate is the local trust boundary behind the telemetry
features presented at `pow.actum.network`. It is a library for IDE, coding-agent, CLI, and build
adapters; it does not enable collection by itself.

## Integration lifecycle

1. Present the five telemetry categories and a plain-language purpose to the developer.
2. Create an `Authorization` with an increasing revision, exact project and immutable policy IDs,
   selected categories, validity start, and explicit retention deadline.
3. Create one `Collector` per authorized project and keep its journal in application-private
   storage. Creation derives `collector_id` from the versioned ML-DSA-44 public-key record.
4. Convert adapter observations to `EventInput`. Supply wall-clock display bounds, monotonic
   duration bounds, units, and separate source, subject, and private-payload commitments.
5. Sign each event through `EventSigner` with the developer or agent ML-DSA-44 key.
6. Call `seal_epoch()` and pass the returned canonical epoch envelope to #775. Sealing durably
   advances the prior-epoch link and preserves collector-wide and project-local sequence counters.
7. Expose pause/resume, JSON export, expiry purge, and local deletion in the application UI.

Every signed event carries its canonical binary envelope, canonical event ID, ML-DSA algorithm
revision, public key, and signature. The signature covers the event ID under
`actum.developer-event.v1`; JSON is never hashed. Reopening a journal verifies every canonical
envelope, ID, signer-derived collector identity, signature, authorization revision, and both
sequence domains before exposing pending evidence.

## Privacy boundary

Do not place prompts, responses, source code, patches, command lines, command output, file paths,
repository remotes, environment variables, account names, or raw model transcripts in `kind`,
`purpose`, `session_id`, or `evidence_commitment`. Derive project and evidence commitments locally
using a project-specific secret so the same project cannot be correlated across installations.

The collector rejects unapproved categories, authorization outside its validity window, inverted
wall or monotonic ranges, zero commitments or units, journal overflow, sequence replay, signer
substitution, canonical-envelope substitution, and signature tampering. Wall-clock span never
determines duration; consumers use the monotonic bounds committed by the event.

## Durability and handoff

Every admitted event and epoch transition is written through a same-directory temporary file,
flushed with `sync_all`, and atomically renamed. Event leaves are
`SHA3-384(0x00 || event_id)`; internal nodes are `SHA3-384(0x01 || left || right)`, with an odd
rightmost node duplicated. `DeveloperEventV1` and `ActivityEpochV1` live in the shared no-std
application-primitives crate so the collector and #776 guest consume exactly one encoding. An
epoch is not finalized until #775 proves its exact anchor statement in finalized Actum state.

The complete wire contract and application API roadmap are in `DEVELOPER_TELEMETRY_V1.md` and
`POW_APP_INTEGRATION_V1.md`. Until #774 through #778 are merged and qualified, the public app must
label collection, proofs, anchoring, verification, and settlement as Preview rather than live.
