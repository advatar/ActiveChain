#!/usr/bin/env python3
"""Regression tests for the fail-closed deterministic-kernel workflow policy."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
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

    def test_main_push_cannot_repeat_the_candidate_gate(self) -> None:
        unsafe = WORKFLOW.replace("    tags: ['v*']", "    branches: [main]\n    tags: ['v*']")
        with self.assertRaisesRegex(ValueError, "must not repeat"):
            POLICY.validate(unsafe)

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

    def test_missing_force_push_reachability_guard_fails_closed(self) -> None:
        unsafe = WORKFLOW.replace('git cat-file -e "${BEFORE_SHA}^{commit}"', "true", 1)
        with self.assertRaisesRegex(ValueError, "before SHA is reachable"):
            POLICY.validate(unsafe)

    def test_missing_force_push_fallback_fails_closed(self) -> None:
        unsafe = WORKFLOW.replace(
            "before SHA is unreachable after force-push; classifying complete PR diff",
            "force push ignored",
            1,
        )
        with self.assertRaisesRegex(ValueError, "conservatively fall back"):
            POLICY.validate(unsafe)

    def classify(self, full: bool, *paths: str) -> dict[str, str]:
        result = subprocess.run(
            ["bash", str(ROOT / "scripts" / "classify-kernel-change-scope.sh"), str(full).lower()],
            input="\n".join(paths) + "\n",
            text=True,
            capture_output=True,
            check=True,
        )
        return dict(line.split("=", 1) for line in result.stdout.splitlines())

    def test_documentation_change_uses_no_arm64_stage(self) -> None:
        scope = self.classify(False, "docs/example.md")
        self.assertEqual({value for key, value in scope.items() if key != "full"}, {"false"})

    def test_ci_core_change_selects_every_stage(self) -> None:
        scope = self.classify(False, ".github/workflows/kernel.yml")
        self.assertEqual({value for key, value in scope.items() if key != "full"}, {"true"})

    def test_full_qualification_selects_every_stage(self) -> None:
        scope = self.classify(True, "docs/example.md")
        self.assertEqual(set(scope.values()), {"true"})

    def test_kanalen_probe_change_selects_runtime(self) -> None:
        scope = self.classify(False, "scripts/test_probe_kanalen_rpc.py")
        self.assertEqual(scope["runtime"], "true")


if __name__ == "__main__":
    unittest.main()
