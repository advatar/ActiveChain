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
- `actum-work-proof-trust-transition`: signature-checked, crash-atomic renewal of that trust store.

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

Trust renewal is a signed transition, including when the previous bundle's time window has expired;
never delete or replace `trust.bin`. Prepare and threshold-sign bundle sequence `N + 1` with the
current signer set and the current finalized checkpoint, then install it atomically with:

```sh
actum-work-proof-trust-transition \
  "$HOME/activechain-deploy/kanalen/work-proof/trust.bin" \
  signed-next-bundle.bin trust-signer-set.bin - "$(($(date +%s) * 1000))"
```

Pass the activated signer-set path instead of `-` only when the preceding bundle explicitly
scheduled that set for this sequence. The command verifies the complete chain, checkpoint
monotonicity, time window, signer-set identity, and threshold signatures before updating the store.
Restart the work-proof service after a successful transition so its in-memory view reloads the new
bundle.

Kanalen is a private developmental testnet with a single operator, so it has one narrower recovery
path that is not a production renewal mechanism. The `trust_rebootstrap_only` workflow generates a
fresh ephemeral 1-of-1 key on the CI runner, binds a sequence-1 bundle to the exact deployed proof
image and finalized checkpoint, and destroys the seed before publishing sanitized evidence. The
host-side installer hard-pins the Kanalen chain ID and genesis commitment, stops the verifier,
refuses the reset if any durable usage has been admitted, archives the prior trust inputs, installs
the candidate atomically, and rolls back unless authenticated health succeeds. Production and any
used network remain transition-only.

Load `dev.activechain.kanalen.work-proof.plist` only after provisioning succeeds. The API listens
on `0.0.0.0:49157` because the gateway runs as a container and reaches the host through
`host.docker.internal`, which cannot dial a loopback-only listener. Every request is still
bearer-authenticated, and only the gateway's `443` is published; `49157` is not forwarded.
The Kanalen gateway terminates TLS for `https://verify.kanalen.actum.network` and pins the
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
| Genesis commitment | `a836c4d201cda6ba33a01aa48011cf5f4d6acdfd1ec409d322dc1b56ed3552a25dcb158e0b1ec0352728653d315d477c` |
| Protocol / RPC schema revision | 1 / 4 |
| Metering policy | `01456c3f54e61fb20466c111f4167916b1ee9d23ac083a0e3ce1662b153c47de27af0a13b09cb5319c24ba31a9cfa8d0`, revision 1 |
| Trust bundle | `d7cf053c9faea38b8bfed6d868ddd6a3b8439e5e7b27d057b262ad6393386ff8db8bfb186e97865d17bc80b7ca6353ed`, sequence 1 |
| Signer set | `95bb3e7016a69e845d7354612aa08a762aa0ada40b7f087a5005e83c0969824c740863869e5c5d1d8ec1d52678f54c94`, 1-of-1 ML-DSA-44 |

A claim's `policy_id` must equal the metering policy above; the verifier rejects any other value.
The policy is emitted canonically by the deployed `actum-work-qualification-source` binary, and the
unused-testnet trust reset derives the ID from that exact binary instead of copying it into workflow
logic. The ephemeral reset signer is acceptable only for this private testnet; production requires
a separately governed N-of-M authority and transition-only renewal.

## Telemetry anchor endpoint

`activechain-telemetry-anchor-gateway` listens on `0.0.0.0:49156` for the same containerised-gateway
reason as the verifier, and is fronted at `https://anchor.kanalen.actum.network`. It serves exactly
two routes:

| Method and path | Body | Auth |
| --- | --- | --- |
| `GET /v1/health` | empty | bearer |
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
export ACTUM_WORK_VERIFIER_URL="https://verify.kanalen.actum.network/v1/proofs/verify"
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

The production lifecycle passed on 2026-08-23 for ActiveChain
`955a976821f16428f7c18f99d6de338d2ace3c33`, ProofOfWork
`d8a49fe7f0817c4805df1db5e06c7c4e00b89795`, and deployment bundle SHA-256
`2d8b12f1025a350832f88fb1c3887a2bdd1619860a0d8a3dfba9b0aa46dd29da`. The sanitized
production artifact is published in issue #778. Deployment run `32639250086` and independent
post-lifecycle status run `32639496465` prove the exact public origins, protected-service health,
one durable receipt, finalized height 8774, checkpoint height 8773, and trust bundle above.

This qualifies the bounded private-testnet lifecycle implementation; it does not claim
production-scale readiness for the Preview whole-file usage registry. The exact final
deterministic-kernel gate passed candidate `a7e55091ba2672b5b7b21483aa7a63ccfe7b582d` in run
`32642557878`; integration into `main` remains the final completion condition.
