---
name: actum-telemetry
description: Manage permissioned Actum developer telemetry, project attribution, work-proof generation, delivery, anchoring, and verification. Use when asked about pow.actum.network, telemetry authorization, pause/resume/export/delete, activity epochs, proof delivery, finalized anchors, or work verification.
license: Apache-2.0
compatibility: Requires Python 3.11+ on a POSIX host. Mutations require ACTUM_TELEMETRY_CAPABILITY. Optional delivery and anchoring require ACTUM_DELIVERY_WEBHOOK and ACTUM_ANCHOR_URL.
metadata:
  author: activechain-contributors
  version: "0.1.0"
---

# Actum telemetry and work proofs

Use the `actum-telemetry` MCP server. Begin with `telemetry.status`; do not infer authorization or
network identity from local files. Collection defaults paused and categories default off.

Every mutation requires an explicit `request_id`, exact 96-character lowercase `project_id`, and
the operator-provided capability. Never display, log, persist, or repeat the capability. Authorize
only categories and retention explicitly requested by the developer.

`telemetry.pause` and `telemetry.resume` control collection independently from the node lifecycle.
`telemetry.export` and `telemetry.delete` are project-scoped local operations. MCP never receives a
collector signing key and observations proposed by an agent are not trusted human-attention proof.

`work.prove`, `work.deliver`, `work.anchor`, and `work.verify` operate only on existing bounded
artifacts. Delivery does not imply anchoring; anchoring does not imply finality; finality does not
imply usage-nullifier admission. Report `relation_verified`, `anchor_verified`, and
`usage_verified` separately whenever available.

`ACTUM_DELIVERY_WEBHOOK` and `ACTUM_ANCHOR_URL` are optional Preview integrations until their exact
deployed revisions pass #775/#778 qualification. Missing, pending, stale, malformed, wrong-chain,
or unavailable results must never be described as verified.
