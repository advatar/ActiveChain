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
