#!/usr/bin/env python3

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "capture_kanalen_pow_status", ROOT / "scripts/capture-kanalen-pow-status.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CaptureKanalenPowStatusTests(unittest.TestCase):
    revision = "a" * 40
    chain = "b" * 96
    genesis = "c" * 96

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        release = self.root / "releases" / self.revision
        release.mkdir(parents=True)
        (release / ".archive.sha256").write_text("d" * 64 + "\n")
        (self.root / "current").symlink_to(release)
        (self.root / "network.env").write_text(
            f"ACTIVECHAIN_CHAIN_ID_HEX={self.chain}\n"
            f"ACTIVECHAIN_GENESIS_COMMITMENT_HEX={self.genesis}\n"
            "ACTIVECHAIN_NETWORK_DOMAIN=kanalen.activechain.dev\n"
        )
        self.tokens = {}
        for area, byte in (("work-delivery", "x"), ("anchor", "y"), ("work-proof", "z")):
            directory = self.root / area
            directory.mkdir()
            token = (byte * 48).encode()
            path = directory / "bearer.token"
            path.write_bytes(token)
            path.chmod(0o600)
            self.tokens[area] = token

    def tearDown(self):
        self.temp.cleanup()

    def probe(self, url, token, _timeout):
        unauthorized = {"status": "error", "code": "unauthorized"}
        identity = {"chain_id": self.chain, "genesis_commitment": self.genesis}
        if "49158" in url or "delivery.kanalen" in url:
            return 200, {
                **identity,
                "status": "healthy",
                "deployment_revision": self.revision,
                "durable_receipts": 3,
            }
        if "49156" in url or "anchor.kanalen" in url:
            if token is None:
                return 401, unauthorized
            self.assertEqual(token, self.tokens["anchor"])
            return 200, {**identity, "status": "healthy", "finalized_height": 42}
        if "49157" in url or "verify.kanalen" in url:
            if token is None:
                return 401, unauthorized
            self.assertEqual(token, self.tokens["work-proof"])
            return 200, {
                **identity,
                "status": "healthy",
                "checkpoint_height": 40,
                "trust_bundle_id": "e" * 96,
                "trust_bundle_sequence": 2,
                "verifier_revision": 1,
                "proof_system_revision": 1,
            }
        raise AssertionError(url)

    def test_capture_binds_exact_revision_and_never_serializes_credentials(self):
        evidence, qualified = MODULE.capture(self.root, self.revision, 1.0, self.probe)
        self.assertTrue(qualified)
        self.assertTrue(evidence["deployment_preflight_qualified"])
        self.assertFalse(evidence["production_qualified"])
        self.assertEqual(evidence["services"]["delivery"]["durable_receipts"], 3)
        encoded = json.dumps(evidence)
        for token in self.tokens.values():
            self.assertNotIn(token.decode(), encoded)

    def test_public_delivery_transport_failure_fails_closed(self):
        def failing_probe(url, token, timeout):
            if "delivery.kanalen" in url:
                raise MODULE.ProbeFailure("transport_unavailable")
            return self.probe(url, token, timeout)

        evidence, qualified = MODULE.capture(self.root, self.revision, 1.0, failing_probe)
        self.assertFalse(qualified)
        self.assertEqual(evidence["production_reason"], "deployment preflight failed")
        delivery = next(
            check for check in evidence["checks"] if check["id"] == "public_delivery_tls_health"
        )
        self.assertEqual(delivery["reason"], "transport_unavailable")

    def test_typed_verifier_failure_is_sanitized_but_preserved(self):
        def stale_probe(url, token, timeout):
            if ("49157" in url or "verify.kanalen" in url) and token is not None:
                return 503, {
                    "status": "error",
                    "error": {"code": "stale_trust", "retryable": False},
                }
            return self.probe(url, token, timeout)

        evidence, qualified = MODULE.capture(self.root, self.revision, 1.0, stale_probe)
        self.assertFalse(qualified)
        verifier = next(
            check for check in evidence["checks"] if check["id"] == "local_verifier_status"
        )
        self.assertEqual(verifier["reason"], "stale_trust")

    def test_rejects_non_private_token_before_any_probe(self):
        (self.root / "anchor" / "bearer.token").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "not private"):
            MODULE.capture(self.root, self.revision, 1.0, self.probe)


if __name__ == "__main__":
    unittest.main()
