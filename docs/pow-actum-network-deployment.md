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
on `127.0.0.1:49157`; the Kanalen gateway terminates TLS for
`https://verify.kanalen.activechain.dev`.

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
