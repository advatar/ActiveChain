#!/usr/bin/env python3
"""Dependency-free conformance gate for the shared cognitive-health demo envelope."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/cognitive-health-demo/v1/demo-event-envelope.schema.json"
VECTOR_PATH = ROOT / "fixtures/cognitive-health-demo/v1/golden-observation-projected.json"
EXPECTED_SCHEMA_SHA256 = "b2c5dd70f447b4f9665d354510eec742cd82c3c5147425bc45ca3409ba5456c1"


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_event(event: dict[str, Any], schema: dict[str, Any]) -> None:
    properties = schema["properties"]
    required = set(schema["required"])
    require(required <= event.keys(), f"missing required fields: {sorted(required - event.keys())}")
    require(set(event) <= set(properties), f"unknown top-level fields: {sorted(set(event) - set(properties))}")
    require(event["schema"] == properties["schema"]["const"], "wrong schema identity")
    require(re.fullmatch(r"[0-9a-f]{32}", event["trace_id"]) is not None, "invalid trace_id")
    require(isinstance(event["sequence"], int) and event["sequence"] >= 0, "invalid sequence")
    datetime.fromisoformat(event["emitted_at"].replace("Z", "+00:00"))
    require(event["producer"] in properties["producer"]["enum"], "unknown producer")
    require(event["event_type"] in properties["event_type"]["enum"], "unknown event_type")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", event["payload_digest"]) is not None, "invalid payload digest")

    privacy = event["privacy"]
    require(set(privacy) == {"classification", "synthetic", "contains_raw_health_data"}, "invalid privacy shape")
    require(privacy["classification"] in {"synthetic", "phi-free-commitment"}, "invalid privacy classification")
    require(privacy["synthetic"] is True, "demo events must be synthetic")
    require(privacy["contains_raw_health_data"] is False, "raw health data is forbidden")

    display = event["display"]
    require(set(display) == {"lane", "title", "summary", "status"}, "invalid display shape")
    require(display["lane"] in properties["display"]["properties"]["lane"]["enum"], "unknown display lane")
    require(display["status"] in properties["display"]["properties"]["status"]["enum"], "unknown display status")
    require(1 <= len(display["title"]) <= 96, "invalid display title")
    require(1 <= len(display["summary"]) <= 280, "invalid display summary")


def expect_rejection(event: dict[str, Any], schema: dict[str, Any], mutation: str) -> None:
    try:
        validate_event(event, schema)
    except (ContractError, TypeError, ValueError):
        return
    raise ContractError(f"negative mutation was accepted: {mutation}")


def main() -> None:
    schema_bytes = SCHEMA_PATH.read_bytes()
    actual_sha = hashlib.sha256(schema_bytes).hexdigest()
    require(actual_sha == EXPECTED_SCHEMA_SHA256, f"schema drift: expected {EXPECTED_SCHEMA_SHA256}, got {actual_sha}")
    schema = json.loads(schema_bytes)
    event = load_json(VECTOR_PATH)
    validate_event(event, schema)

    raw_data = copy.deepcopy(event)
    raw_data["privacy"]["contains_raw_health_data"] = True
    expect_rejection(raw_data, schema, "raw health data")

    unknown_model = copy.deepcopy(event)
    unknown_model["producer"] = "opaque-general-model"
    expect_rejection(unknown_model, schema, "unknown producer")

    injected = copy.deepcopy(event)
    injected["raw_payload"] = {"glucose": 10.2}
    expect_rejection(injected, schema, "unknown raw payload")

    print(f"cognitive-health demo contract valid: {actual_sha}")


if __name__ == "__main__":
    main()
