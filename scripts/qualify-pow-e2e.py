#!/usr/bin/env python3
"""Run deterministic pow.actum.network rehearsals and emit exact-revision evidence."""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "testing/pow/qualification-matrix-v1.json"
CONSUMER = ROOT / "testing/contracts/proof-of-work-verifier-v1.json"
ADMISSION_SCHEMA = ROOT / "schemas/actum-work-proof-admission-v1.schema.json"
TYPESCRIPT_CLIENT = ROOT / "docs/examples/pow-work-proof-client.ts"
REVISION = re.compile(r"^[0-9a-f]{40,64}$")


def run(command: list[str], environment: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=ROOT, env=environment, check=True)


def validate_consumer_contract() -> None:
    contract = json.loads(CONSUMER.read_text("utf-8"))
    request = contract["request"]
    assert set(request) == {"schema", "operation", "profile", "proof", "expected"}
    assert request["schema"] == "actum.work-proof.verify.request.v1"
    assert request["operation"] == "verify_non_overlap"
    assert request["profile"] == "actum.non-overlap.risc0.v1"
    results = contract["results"]
    assert [result["code"] for result in results] == [
        "VERIFIED",
        "INVALID",
        "UNSUPPORTED",
        "MALFORMED",
    ]
    assert all(result["verified"] == (result["code"] == "VERIFIED") for result in results)
    stateful_request = contract["stateful_request"]
    assert set(stateful_request) == {
        "schema",
        "operation",
        "profile",
        "claim_id",
        "public_claim_envelope_hex",
        "proof_envelope_hex",
        "anchor_request_envelope_hex",
        "checkpointed_anchor_evidence_envelope_hex",
    }
    assert stateful_request["schema"] == "actum.work-proof.admit.request.v1"
    assert stateful_request["operation"] == "verify_and_register"
    assert stateful_request["profile"] == "actum.non-overlap.risc0.v1"
    assert "trust_bundle" not in stateful_request
    stateful_result = contract["stateful_result"]
    assert set(stateful_result) == {"schema", "result"}
    assert stateful_result["schema"] == "actum.work-proof.admit.result.v1"
    claim = stateful_result["result"]
    assert set(claim) == {
        "claim_id",
        "lifecycle",
        "relation_verified",
        "anchor_verified",
        "usage_verified",
        "idempotent",
        "chain_id",
        "project_id",
        "usage_domain",
        "policy_id",
        "policy_revision",
        "aggregate",
        "anchor",
        "accepted_at_ms",
    }
    assert claim["lifecycle"] == "anchor_finalized"
    assert all(claim[field] for field in ("relation_verified", "anchor_verified", "usage_verified"))
    schema = json.loads(ADMISSION_SCHEMA.read_text("utf-8"))
    request_schema = schema["$defs"]["request"]
    assert request_schema["additionalProperties"] is False
    assert set(request_schema["required"]) == set(stateful_request) - {
        "checkpointed_anchor_evidence_envelope_hex"
    }
    checkpointed_evidence = request_schema["properties"][
        "checkpointed_anchor_evidence_envelope_hex"
    ]
    assert {entry.get("type") for entry in checkpointed_evidence["oneOf"]} == {"null", None}
    assert "trust_bundle" not in request_schema["properties"]
    error_codes = set(schema["$defs"]["errorCode"]["enum"])
    assert {"checkpoint_lag", "checkpoint_unavailable"} <= error_codes
    client = TYPESCRIPT_CLIENT.read_text("utf-8")
    for required in (
        "actum.work-proof.admit.request.v1",
        "actum.work-proof.admit.result.v1",
        "application/vnd.actum.work-proof.v1+json",
        "relation_verified",
        "anchor_verified",
        "usage_verified",
    ):
        assert required in client


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if not REVISION.fullmatch(arguments.revision):
        raise SystemExit("revision must be an exact lowercase Git object ID")

    matrix = json.loads(MATRIX.read_text("utf-8"))
    cases = matrix["cases"]
    identifiers = [case["id"] for case in cases]
    if len(identifiers) != len(set(identifiers)) or not identifiers:
        raise SystemExit("qualification matrix identifiers must be unique")
    deterministic = [case for case in cases if case["tier"] == "deterministic"]
    production = [case for case in cases if case["tier"] == "production"]
    if not deterministic or not production:
        raise SystemExit("both deterministic and production evidence tiers are required")

    run([sys.executable, "-m", "unittest", "testing/plugin/test_actum_telemetry_plugin.py"])
    run([sys.executable, "scripts/check-developer-telemetry-contract.py"])
    rust_environment = os.environ.copy()
    rust_environment.pop("RISC0_SKIP_BUILD", None)
    run(
        [
            "cargo",
            "test",
            "--locked",
            "--release",
            "-p",
            "activechain-work-proof-verifier",
            "--lib",
        ],
        rust_environment,
    )
    validate_consumer_contract()

    guide = (ROOT / "docs/POW_APP_INTEGRATION_V1.md").read_text("utf-8")
    if "**Preview**" not in guide or "relation_verified" not in guide:
        raise SystemExit("developer guide must retain Preview and dimensioned verification rules")

    evidence = {
        "$schema": "https://actum.network/evidence/pow-deterministic-qualification/v1",
        "revision": arguments.revision,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "deterministic_qualified": True,
        "production_qualified": False,
        "production_reason": "real deployment evidence is a separate mandatory artifact",
        "cases": [
            {"id": case["id"], "result": "passed", "source": case["source"]}
            for case in deterministic
        ]
        + [
            {"id": case["id"], "result": "not_evaluated", "source": case["source"]}
            for case in production
        ],
    }
    arguments.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", "utf-8")
    print(f"pow deterministic qualification passed for {arguments.revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
