#!/usr/bin/env python3
"""Fast deterministic consistency checks for the developer telemetry contract."""

import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "testing/schemas/developer-telemetry-v1.schema.json"
VECTOR = ROOT / "testing/vectors/developer-telemetry-v1.json"
GUIDE = ROOT / "docs/POW_APP_INTEGRATION_V1.md"
CONTRACT = ROOT / "docs/DEVELOPER_TELEMETRY_V1.md"
THREAT = ROOT / "docs/DEVELOPER_TELEMETRY_THREAT_MODEL_V1.md"


def require_digest(value: str) -> None:
    assert re.fullmatch(r"[0-9a-f]{96}", value), value


schema = json.loads(SCHEMA.read_text())
vector = json.loads(VECTOR.read_text())
assert schema["$id"] == "https://actum.network/schemas/developer-telemetry-v1.schema.json"
assert vector["profile"] == "actum.developer-telemetry.v1"
assert set(schema["$defs"]) == {
    "digest384", "digest256", "u64", "event", "signed_event", "epoch", "policy",
    "claim", "anchor", "proof_envelope", "verification"
}

for signed in vector["events"]:
    event = signed["event"]
    for field in ("collector_id", "project_id", "source_commitment", "subject_commitment", "payload_commitment"):
        require_digest(event[field])
    require_digest(signed["event_id"])
    assert event["wall_start_ms"] <= event["wall_end_ms"]
    assert event["monotonic_start_ns"] <= event["monotonic_end_ns"]
for epoch in vector["epochs"]:
    for field in ("epoch_id", "collector_id", "project_id", "event_root", "prior_epoch_id", "policy_id"):
        require_digest(epoch[field])
    assert epoch["event_count"] == epoch["last_sequence"] - epoch["first_sequence"] + 1
for envelope in vector["proofs"]:
    claim = envelope["claim"]
    require_digest(claim["claim_id"])
    assert claim["interval_start_ms"] <= claim["interval_end_ms"]
    assert envelope["anchor"]["status"] != "finalized" or envelope["anchor"]["evidence_envelope"]
assert {result["status"] for result in vector["verification_results"]} >= {"pending", "invalid"}

combined = "\n".join(path.read_text() for path in (GUIDE, CONTRACT, THREAT))
for required in (
    "AttentionProofV1", "ComputeProofV1", "ContributionProofV1", "NonOverlapProofV1",
    "Installation does not authorize collection", "wall-clock", "wrong-network",
    "pow.actum.network", "#773", "#774", "#775", "#776", "#777", "#778",
):
    assert required in combined, required
print("developer telemetry contract: passed")
