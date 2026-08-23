#!/usr/bin/env python3
"""Capture sanitized, fail-closed status for the deployed Kanalen PoW services."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from typing import Any, Callable
import urllib.error
import urllib.request

REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST384 = re.compile(r"^[0-9a-f]{96}$")
DIGEST256 = re.compile(r"^[0-9a-f]{64}$")
MAX_RESPONSE_BYTES = 64 * 1024


class ProbeFailure(Exception):
    """A sanitized transport or response failure."""


def read_environment(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator or not name or name in values:
            raise ValueError("malformed network environment")
        values[name] = value
    return values


def read_private_token(path: Path) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("credential file is not private")
    token = path.read_bytes().rstrip()
    if not 32 <= len(token) <= 256 or any(not 0x21 <= byte <= 0x7E for byte in token):
        raise ValueError("credential file is malformed")
    return token


def http_probe(url: str, token: bytes | None, timeout: float) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token.decode("ascii")
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        raise ProbeFailure("transport_unavailable") from error
    try:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ProbeFailure("oversized_response")
        value = json.loads(body) if body else {}
        if not isinstance(value, dict):
            raise ProbeFailure("malformed_response")
        return response.status, value
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeFailure("malformed_response") from error
    finally:
        response.close()


def capture(
    root: Path,
    expected_revision: str,
    timeout: float,
    probe: Callable[[str, bytes | None, float], tuple[int, dict[str, Any]]] = http_probe,
) -> tuple[dict[str, Any], bool]:
    if not REVISION.fullmatch(expected_revision):
        raise ValueError("expected revision must be a full lowercase Git commit")
    root = root.resolve()
    current_link = root / "current"
    if not current_link.is_symlink():
        raise ValueError("current release is not a symlink")
    current = current_link.resolve(strict=True)
    expected_release = (root / "releases" / expected_revision).resolve(strict=True)
    if current != expected_release:
        raise ValueError("active release does not match expected revision")
    archive_digest = (current / ".archive.sha256").read_text("ascii").strip()
    if not DIGEST256.fullmatch(archive_digest):
        raise ValueError("release archive digest is malformed")

    network = read_environment(root / "network.env")
    chain_id = network.get("ACTIVECHAIN_CHAIN_ID_HEX", "")
    genesis = network.get("ACTIVECHAIN_GENESIS_COMMITMENT_HEX", "")
    domain = network.get("ACTIVECHAIN_NETWORK_DOMAIN", "")
    if not DIGEST384.fullmatch(chain_id) or not DIGEST384.fullmatch(genesis):
        raise ValueError("runtime network identity is malformed")
    if domain != "kanalen.activechain.dev":
        raise ValueError("unexpected deployed network domain")

    delivery_token = read_private_token(root / "work-delivery" / "bearer.token")
    anchor_token = read_private_token(root / "anchor" / "bearer.token")
    verifier_token = read_private_token(root / "work-proof" / "bearer.token")
    checks: list[dict[str, Any]] = []

    def check(
        identifier: str,
        url: str,
        token: bytes | None,
        expected_status: int,
        validator: Callable[[dict[str, Any]], bool],
    ) -> dict[str, Any] | None:
        try:
            status_code, body = probe(url, token, timeout)
            passed = status_code == expected_status and validator(body)
            error = body.get("error")
            typed_reason = error.get("code") if isinstance(error, dict) else body.get("code")
            reason = typed_reason if isinstance(typed_reason, str) else "unexpected_response"
            checks.append(
                {
                    "id": identifier,
                    "result": "passed" if passed else "failed",
                    "http_status": status_code,
                    "reason": None if passed else reason,
                }
            )
            return body if passed else None
        except ProbeFailure as error:
            checks.append(
                {
                    "id": identifier,
                    "result": "failed",
                    "http_status": None,
                    "reason": str(error),
                }
            )
            return None

    identity = lambda body: (
        body.get("chain_id") == chain_id and body.get("genesis_commitment") == genesis
    )
    delivery = check(
        "local_delivery_health",
        "http://127.0.0.1:49158/v1/health",
        None,
        200,
        lambda body: identity(body)
        and body.get("status") == "healthy"
        and body.get("deployment_revision") == expected_revision
        and isinstance(body.get("durable_receipts"), int),
    )
    anchor = check(
        "local_anchor_health",
        "http://127.0.0.1:49156/v1/health",
        anchor_token,
        200,
        lambda body: identity(body)
        and body.get("status") == "healthy"
        and isinstance(body.get("finalized_height"), int),
    )
    verifier = check(
        "local_verifier_status",
        "http://127.0.0.1:49157/v1/status",
        verifier_token,
        200,
        lambda body: identity(body)
        and body.get("status") == "healthy"
        and isinstance(body.get("checkpoint_height"), int)
        and isinstance(body.get("trust_bundle_sequence"), int),
    )
    check(
        "local_anchor_rejects_unauthorized",
        "http://127.0.0.1:49156/v1/health",
        None,
        401,
        lambda body: body.get("code") == "unauthorized",
    )
    check(
        "local_verifier_rejects_unauthorized",
        "http://127.0.0.1:49157/v1/status",
        None,
        401,
        lambda body: body.get("code") == "unauthorized",
    )
    origins = {
        "delivery": "https://delivery.kanalen.actum.network",
        "anchor": f"https://anchor.{domain}",
        "verifier": f"https://verify.{domain}",
    }
    check(
        "public_delivery_tls_health",
        origins["delivery"] + "/v1/health",
        None,
        200,
        lambda body: identity(body)
        and body.get("deployment_revision") == expected_revision,
    )
    check(
        "public_anchor_rejects_unauthorized",
        origins["anchor"] + "/v1/health",
        None,
        401,
        lambda body: body.get("code") == "unauthorized",
    )
    check(
        "public_anchor_authenticated_health",
        origins["anchor"] + "/v1/health",
        anchor_token,
        200,
        lambda body: identity(body) and body.get("status") == "healthy",
    )
    check(
        "public_verifier_rejects_unauthorized",
        origins["verifier"] + "/v1/status",
        None,
        401,
        lambda body: body.get("code") == "unauthorized",
    )
    check(
        "public_verifier_authenticated_status",
        origins["verifier"] + "/v1/status",
        verifier_token,
        200,
        lambda body: identity(body) and body.get("status") == "healthy",
    )

    qualified = all(item["result"] == "passed" for item in checks)
    evidence: dict[str, Any] = {
        "$schema": "https://actum.network/evidence/pow-deployment-status/v1",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "activechain_revision": expected_revision,
        "deployment_bundle_sha256": archive_digest,
        "network": {
            "chain_id": chain_id,
            "genesis_commitment": genesis,
            "domain": domain,
            "public_origins": origins,
        },
        "services": {
            "delivery": {
                "deployment_revision": delivery.get("deployment_revision") if delivery else None,
                "durable_receipts": delivery.get("durable_receipts") if delivery else None,
            },
            "anchor": {
                "finalized_height": anchor.get("finalized_height") if anchor else None,
            },
            "verifier": {
                "checkpoint_height": verifier.get("checkpoint_height") if verifier else None,
                "trust_bundle_id": verifier.get("trust_bundle_id") if verifier else None,
                "trust_bundle_sequence": verifier.get("trust_bundle_sequence") if verifier else None,
                "verifier_revision": verifier.get("verifier_revision") if verifier else None,
                "proof_system_revision": verifier.get("proof_system_revision") if verifier else None,
            },
        },
        "credential_permissions": "private_regular_files",
        "checks": checks,
        "deployment_preflight_qualified": qualified,
        "production_qualified": False,
        "production_reason": (
            "state-changing lifecycle evidence remains mandatory"
            if qualified
            else "deployment preflight failed"
        ),
    }
    serialized = json.dumps(evidence, sort_keys=True).encode("utf-8")
    for token in (delivery_token, anchor_token, verifier_token):
        if token in serialized or hashlib.sha256(token).hexdigest().encode("ascii") in serialized:
            raise ValueError("credential material reached sanitized evidence")
    return evidence, qualified


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--deployment-root",
        type=Path,
        default=Path.home() / "activechain-deploy" / "kanalen",
    )
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    arguments = parser.parse_args()
    if not 1.0 <= arguments.timeout_seconds <= 60.0:
        raise SystemExit("timeout must be between 1 and 60 seconds")
    try:
        evidence, qualified = capture(
            arguments.deployment_root,
            arguments.expected_revision,
            arguments.timeout_seconds,
        )
    except (OSError, ValueError) as error:
        evidence = {
            "$schema": "https://actum.network/evidence/pow-deployment-status/v1",
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "activechain_revision": arguments.expected_revision,
            "deployment_preflight_qualified": False,
            "production_qualified": False,
            "production_reason": "local deployment state is invalid",
            "checks": [
                {
                    "id": "local_deployment_state",
                    "result": "failed",
                    "http_status": None,
                    "reason": error.__class__.__name__,
                }
            ],
        }
        qualified = False
    encoded = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if str(arguments.output) == "-":
        sys.stdout.write(encoded)
    else:
        arguments.output.write_text(encoded, "utf-8")
    return 0 if qualified else 2


if __name__ == "__main__":
    raise SystemExit(main())
