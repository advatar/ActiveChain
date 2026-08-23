#!/usr/bin/env python3

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "qualification_http", ROOT / "deploy/kanalen/scripts/qualification-http.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class QualificationHttpTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_private_token_rejects_public_mode_and_symlink(self):
        token = self.root / "token"
        token.write_text("x" * 48)
        token.chmod(0o600)
        self.assertEqual(MODULE.private_token(token), "x" * 48)
        token.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "rejected"):
            MODULE.private_token(token)
        token.chmod(0o600)
        link = self.root / "link"
        link.symlink_to(token)
        with self.assertRaisesRegex(ValueError, "rejected"):
            MODULE.private_token(link)

    def test_anchor_extraction_is_exact_and_bounded(self):
        artifact = self.root / "artifact.json"
        artifact.write_text(json.dumps({"anchor_request_envelope_hex": "0123abcd"}))
        self.assertEqual(MODULE.anchor_bytes(artifact), bytes.fromhex("0123abcd"))
        artifact.write_text(json.dumps({"anchor_request_envelope_hex": "ABCDEF"}))
        with self.assertRaisesRegex(ValueError, "canonical"):
            MODULE.anchor_bytes(artifact)


if __name__ == "__main__":
    unittest.main()
