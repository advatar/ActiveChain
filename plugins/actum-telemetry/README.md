# Actum telemetry Agent Plugin

Portable Agent Plugins 1.0.0 and Codex package for the privacy-bounded telemetry contract used by
`pow.actum.network`. The client supplies `PLUGIN_DATA`; the operator separately supplies
`ACTUM_TELEMETRY_CAPABILITY` for mutating calls.

The MCP server stores only authorization/control metadata and idempotency receipts. It does not
hold collector signing keys, accept raw source/prompts/output, or silently enable collection.
`ACTUM_DELIVERY_WEBHOOK` and `ACTUM_ANCHOR_URL` are optional Preview integrations. Their presence is
reported without exposing values. Delivery and anchoring remain orthogonal lifecycle states.
