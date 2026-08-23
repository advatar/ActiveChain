# Actum telemetry Agent Plugin

Portable Agent Plugins 1.0.0 and Codex package for the privacy-bounded telemetry contract used by
`pow.actum.network`. The client supplies `PLUGIN_DATA`; the operator separately supplies
`ACTUM_TELEMETRY_CAPABILITY` for mutating calls.

The MCP server stores only authorization/control metadata and idempotency receipts. It does not
hold collector signing keys, accept raw source/prompts/output, or silently enable collection.
`ACTUM_DELIVERY_WEBHOOK` is an optional Preview delivery integration and is usable only with a
regular, non-symlink mode-0600 `ACTUM_DELIVERY_BEARER_TOKEN_FILE`. Anchoring similarly needs
`ACTUM_ANCHOR_URL` and `ACTUM_ANCHOR_BEARER_TOKEN_FILE`. Configuration presence is reported without
exposing values or bearer material. Delivery and anchoring remain orthogonal lifecycle states.

`submitted` delivery and `submitted`/`pending` anchor results are refreshable with the same
canonical request ID. Terminal results are served from the durable idempotency journal. A
`VERIFIED` result from the stateless RISC Zero JSON adapter is reported only as
`relation_verified`; it never sets `anchor_verified` or `usage_verified`.

For stateful admission, configure `ACTUM_WORK_VERIFIER_URL` with the deployed HTTPS
`/v1/proofs/verify` endpoint and `ACTUM_WORK_VERIFIER_BEARER_TOKEN_FILE` with a regular,
non-symlink mode-0600 token file. `work.verify` then submits the canonical
`actum.work-proof.admit.request.v1` artifact and reports `verified` only when the service returns
the exact v1 result with relation, finalized anchor, and atomic usage admission all verified and
bound to the authorized chain, project, policy ID, and policy revision. Operator-selected trust is
held by the service and is never accepted from plugin arguments. If the stateful URL is configured
incorrectly, verification fails closed rather than falling back. `ACTUM_WORK_VERIFIER` remains the
explicit stateless relation-only subprocess fallback when no stateful URL is configured.

For proof generation, run `actum-work-prover --serve /absolute/private/config.json`, set
`ACTUM_WORK_PROVER` to that same absolute executable, set `ACTUM_WORK_PROVER_SOCKET` to the
daemon's private mode-0600 Unix socket, and optionally set
`ACTUM_WORK_PROVER_TIMEOUT_SECONDS` to a bounded 30–900 second value (default 600). The config pins
the chain, genesis, usage domain, submitter, canonical policy envelope, private claimant-secret
file, mode-0700 output directory inside `PLUGIN_DATA`, absolute socket path, and absolute `r0vm`
path. `work.prove` accepts only an `actum.work-claim.source.v1` artifact emitted from the Rust
collector's signed sealed epoch. The
daemon re-verifies every ML-DSA event signature, reconstructs the epoch root and Merkle witnesses,
derives the aggregate and nullifiers, proves the pinned RISC Zero relation, and emits the exact
stateful admission artifact. Proving always occurs in the isolated `r0vm` subprocess, so a native
prover fault cannot terminate the key-owning daemon. From a successful prover call, the plugin
records the exact artifact and anchor request ID and extracts anchor bytes only from that recorded
artifact. It never reads the prover config or claimant secret and never constructs canonical
events, claims, or anchor requests.
