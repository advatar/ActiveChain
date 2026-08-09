# Actum developer telemetry collector v1

The `activechain-developer-telemetry` crate is the local trust boundary behind the telemetry
features presented at `pow.actum.network`. It is a library for IDE, coding-agent, CLI, and build
adapters; it does not enable collection by itself.

## Integration lifecycle

1. Present the five telemetry categories and a plain-language purpose to the developer.
2. Create an `Authorization` with an increasing revision, project-scoped commitment, selected
   categories, and explicit retention deadline.
3. Create one `Collector` per project/session and keep its journal in application-private storage.
4. Convert adapter observations to `EventInput`. Only bounded metadata and an opaque evidence
   commitment are accepted.
5. Sign each event through `EventSigner` with the developer or agent ML-DSA-44 key.
6. Call `epoch()` and pass its Merkle root to the anchoring API implemented by issue #775.
7. Expose pause/resume, JSON export, expiry purge, and local deletion in the application UI.

Every event carries the ML-DSA-44 public key that verifies its signature. Reopening a journal
verifies the complete signature and hash chain before exposing any event. Once a journal contains
an event its policy revision is immutable; an authorization revision starts a new session and
journal so one epoch can never contain claims evaluated under different policies.

## Privacy boundary

Do not place prompts, responses, source code, patches, command lines, command output, file paths,
repository remotes, environment variables, account names, or raw model transcripts in `kind`,
`purpose`, `session_id`, or `evidence_commitment`. Derive project and evidence commitments locally
using a project-specific secret so the same project cannot be correlated across installations.

The collector rejects unapproved categories, expired authorization, inverted time ranges, control
characters, oversized labels, journal overflow, sequence replay, signature substitution, and
hash-chain tampering. A policy replacement must increase the revision, cannot change the bound
project, and is accepted only before the first event is recorded.

## Durability and handoff

Every admitted event is written through a same-directory temporary file, flushed with `sync_all`,
and atomically renamed. Opening a journal revalidates its event sequence and hash chain. The v1
epoch duplicates an odd final leaf and hashes ordered pairs with SHA3-384 under type tag `0x01b3`.
The resulting root is deterministic but is not finalized until issue #775 anchors it and returns an
Actum finality reference.

The complete wire contract and application API roadmap are in `DEVELOPER_TELEMETRY_V1.md` and
`POW_APP_INTEGRATION_V1.md`. Until #774 through #778 are merged and qualified, the public app must
label collection, proofs, anchoring, verification, and settlement as Preview rather than live.
