# `pow.actum.network` stateful verifier deployment

This document defines the production-facing ActiveChain boundary consumed by the
`pow.actum.network` server. The capability remains **Preview** until issue #778 records
successful evidence from the exact deployed revisions.

## Components

The Kanalen release contains:

- `actum-work-proof-api`: authenticated stateful admission and bounded explorer API.
- `actum-work-proof-verifier`: bounded subprocess relation verifier.
- `actum-work-proof-json-verifier`: stateless JSON adapter for diagnostics only.
- `actum-work-proof-trust-bootstrap`: one-time validation and creation of the durable trust store.

Production admission uses the stateful API. The stateless JSON adapter cannot establish
`anchor_verified` or enforce durable usage uniqueness and must not be presented as production
verification.

## Operator provisioning

Install the release under `$HOME/activechain-deploy/kanalen/current`, then place these
operator-authorized canonical binary inputs in `$HOME/activechain-deploy/kanalen/work-proof`:

- `signed-trust-bundle.bin`, mode `0600` or `0400`.
- `trust-signer-set.bin`, mode `0600` or `0400`.

The repository does not generate or choose production trust authority. The operator-supplied
bundle must bind the intended chain, checkpoint, proof image, verifier revision, and metering
policy. Provision durable state with:

```sh
bash "$HOME/activechain-deploy/kanalen/current/scripts/provision-work-proof-verifier.sh"
```

Provisioning creates a random bearer token, validates the signed bundle and signer set through
`actum-work-proof-trust-bootstrap`, and refuses symlinks or group/world-readable secret files. It
is idempotent and does not overwrite an existing token or trust store.

Load `dev.activechain.kanalen.work-proof.plist` only after provisioning succeeds. The API listens
on `0.0.0.0:49157` because the gateway runs as a container and reaches the host through
`host.docker.internal`, which cannot dial a loopback-only listener. Every request is still
bearer-authenticated, and only the gateway's `443` is published; `49157` is not forwarded.
The Kanalen gateway terminates TLS for `https://verify.kanalen.activechain.dev` and pins the
route to `http/1.1` ALPN, because the API speaks HTTP/1.1 and a client that negotiates h2
otherwise fails on the first response frame.

An explicitly enabled `testnet-deploy.yml` run uploads the archive and checksum, verifies and
extracts the exact Git revision under `releases/`, provisions trust before changing the `current`
symlink, reloads the complete launchd set, and validates/restarts the versioned Traefik gateway
while preserving its ACME state. Archive path traversal, checksum mismatch, chain-ID substitution,
missing binaries, missing trust, malformed launch agents, and invalid gateway configuration fail
the activation.

## Current Kanalen testnet identity

The chain was rebuilt from current code on 2026-08-11; the Aug 2 state predated native anchoring and
its execution state could not satisfy the anchor-operator requirement. The chain ID is derived from
the network domain and therefore survived the rebuild, but the genesis commitment did not. Any
client pinning the previous genesis rejects this chain until re-pinned.

| Value | |
| --- | --- |
| Chain ID | `b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0b095e6cfe944bd2c9f6535b4c927782f1` |
| Genesis commitment | `f600eb4a562a3acd2bd82e46fa8ee063217153f827af12300c35fcb1b75fc96ab5650477691a6ce1b4350a314e5dbca4` |
| Protocol / RPC schema revision | 1 / 2 |
| Metering policy | `a7c9d070a32fbc81a154ee8f9ca9ab475ab97bd8f6760645601f2638a8235c44dfd86c395a843182ef65dd5385849cf8`, revision 1 |
| Trust bundle | `a2dfafd2f37912d73f8e12ecf739ae9d83ed1abdfb16405978315da33d1528ce939f31a8a14e177b6d9deca9646d36f2`, sequence 1 |
| Signer set | `95bb3e7016a69e845d7354612aa08a762aa0ada40b7f087a5005e83c0969824c740863869e5c5d1d8ec1d52678f54c94`, 1-of-1 ML-DSA-44 |

A claim's `policy_id` must equal the metering policy above; the verifier rejects any other value. The
bootstrap signer is a single offline ML-DSA-44 root held off the verifier host, which is acceptable
for a testnet bootstrap only: the format is threshold-capable and production requires migrating to a
separated N-of-M set before promotion.

## Telemetry anchor endpoint

`activechain-telemetry-anchor-gateway` listens on `0.0.0.0:49156` for the same containerised-gateway
reason as the verifier, and is fronted at `https://anchor.kanalen.activechain.dev`. It serves exactly
two routes:

| Method and path | Body | Auth |
| --- | --- | --- |
| `GET /v1/health` | empty | none |
| `POST /v1/anchors` | canonical `TelemetryEpochAnchorRequestV1` **binary envelope** | bearer |

The request body is a canonical envelope, not JSON. There is no JSON anchor-submission schema, and
`ACTUM_ANCHOR_URL` must address `POST /v1/anchors` on this gateway. An application that posts a JSON
document is rejected regardless of its contents.

Applications must not build that envelope themselves. Canonical event identity, sequencing,
monotonic durations, and epoch Merkle structure are constructed only by an Actum-owned telemetry
authority, as `DEVELOPER_TELEMETRY_V1.md` requires; an application that assembles its own envelope
duplicates the canonical encoder and drifts from it. Submit raw observations to the collector and
let it produce the epoch and the anchor request.

## ProofOfWork server configuration

Configure only the server-side application process:

```sh
export ACTUM_WORK_VERIFIER_URL="https://verify.kanalen.activechain.dev/v1/proofs/verify"
export ACTUM_WORK_VERIFIER_BEARER_TOKEN_FILE="/private/path/to/work-proof-verifier.token"
```

The token file must be a regular non-symlink file with mode `0600` or `0400`. Never expose the
token to browser code, logs, telemetry, or a public repository. The request uses
`Content-Type: application/vnd.actum.work-proof.v1+json` and the schema in
`schemas/actum-work-proof-admission-v1.schema.json`.

A successful application result requires all three booleans to be true:

- `relation_verified`: the pinned proof relation and public journal passed.
- `anchor_verified`: the exact anchor has cryptographic inclusion in finalized Actum state under
  operator-selected trust.
- `usage_verified`: every class-neutral usage nullifier was atomically admitted, or this is an
  idempotent retry of the exact same claim.

Missing trust, stale trust, relation-verifier failure, anchor mismatch, nullifier collision,
authentication failure, timeout, and malformed responses all fail closed. The submitted request
cannot select or replace the trust bundle.

## Promotion evidence

Do not remove the Preview label until the exact deployed collector, epoch, anchor, proof image,
stateful verifier, gateway, and ProofOfWork revisions have passed restart, replay, substitution,
concurrency, stale-trust, delivery, finality, privacy/logging, and failure rehearsals. Preserve the
resulting revision IDs and evidence artifact in issue #778.
