#!/usr/bin/env python3
"""Regression tests for the fail-closed deterministic-kernel workflow policy."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-kernel-workflow-policy.py"
SPEC = importlib.util.spec_from_file_location("kernel_policy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
WORKFLOW = (ROOT / ".github" / "workflows" / "kernel.yml").read_text(encoding="utf-8")


class KernelWorkflowPolicyTests(unittest.TestCase):
    def test_current_workflow_is_complete(self) -> None:
        POLICY.validate(WORKFLOW)

    def test_each_mandatory_command_fails_closed_when_removed(self) -> None:
        for command in POLICY.MANDATORY_COMMANDS:
            with self.subTest(command=command), self.assertRaises(ValueError):
                POLICY.validate(WORKFLOW.replace(command, "removed-command", 1))

    def test_missing_stage_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing mandatory job: kani"):
            POLICY.validate(WORKFLOW.replace("  kani:\n", "  removed-kani:\n", 1))

    def test_incomplete_aggregate_dependency_set_fails_closed(self) -> None:
        incomplete = WORKFLOW.replace(", vectors]", "]", 1)
        with self.assertRaisesRegex(ValueError, "complete stage set"):
            POLICY.validate(incomplete)


if __name__ == "__main__":
    unittest.main()
