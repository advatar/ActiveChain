# Actum telemetry Agent Plugin

Portable Agent Plugins 1.0.0 and Codex package for the privacy-bounded telemetry contract used by
`pow.actum.network`. The client supplies `PLUGIN_DATA`; the operator separately supplies
`ACTUM_TELEMETRY_CAPABILITY` for mutating calls.

The MCP server stores only authorization/control metadata and idempotency receipts. It does not
hold collector signing keys, accept raw source/prompts/output, or silently enable collection.
`ACTUM_DELIVERY_WEBHOOK` is an optional Preview delivery integration. Anchoring additionally needs
`ACTUM_ANCHOR_URL` and `ACTUM_ANCHOR_BEARER_TOKEN_FILE`; the token file must be a regular,
non-symlink mode-0600 file. Configuration presence is reported without exposing values or bearer
material. Delivery and anchoring remain orthogonal lifecycle states.

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
