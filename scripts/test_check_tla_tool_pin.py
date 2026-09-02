#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import tempfile
import unittest

import check_tla_tool_pin


class TLAToolPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary_directory.name)
        for relative in check_tla_tool_pin.RUNNERS + check_tla_tool_pin.PROOF_SCOPES:
            (self.root / relative).parent.mkdir(parents=True, exist_ok=True)
        self._write_valid_fixture()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _write_valid_fixture(self) -> None:
        for relative in check_tla_tool_pin.RUNNERS:
            (self.root / relative).write_text(
                f"tla_asset_id={check_tla_tool_pin.EXPECTED_ASSET_ID}\n"
                f"tla_sha256={check_tla_tool_pin.EXPECTED_SHA256}\n",
                encoding="utf-8",
            )
        for relative in check_tla_tool_pin.PROOF_SCOPES:
            (self.root / relative).write_text(
                "The runner pins immutable GitHub release asset "
                f"`{check_tla_tool_pin.EXPECTED_ASSET_ID}` for TLA+ tools v1.8.0 by SHA-256\n"
                f"`{check_tla_tool_pin.EXPECTED_SHA256}`.\n",
                encoding="utf-8",
            )

    def test_aligned_runner_and_proof_scope_pins_pass(self) -> None:
        check_tla_tool_pin.verify(self.root)

    def test_runner_asset_mismatch_fails_closed(self) -> None:
        runner = self.root / check_tla_tool_pin.RUNNERS[0]
        runner.write_text(
            runner.read_text(encoding="utf-8").replace(
                check_tla_tool_pin.EXPECTED_ASSET_ID, "523952485"
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "expected"):
            check_tla_tool_pin.verify(self.root)

    def test_proof_scope_digest_mismatch_fails_closed(self) -> None:
        proof_scope = self.root / check_tla_tool_pin.PROOF_SCOPES[1]
        proof_scope.write_text(
            proof_scope.read_text(encoding="utf-8").replace(
                check_tla_tool_pin.EXPECTED_SHA256, "0" * 64
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "expected"):
            check_tla_tool_pin.verify(self.root)


if __name__ == "__main__":
    unittest.main()
