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
SETUP_ACTION = (ROOT / ".github" / "actions" / "kernel-setup" / "action.yml").read_text(
    encoding="utf-8"
)


class KernelWorkflowPolicyTests(unittest.TestCase):
    def test_current_workflow_is_complete(self) -> None:
        POLICY.validate(WORKFLOW)

    def test_current_setup_action_is_complete(self) -> None:
        POLICY.validate_setup(SETUP_ACTION)

    def test_formal_models_require_anonymous_docker(self) -> None:
        unsafe = WORKFLOW.replace(
            "with: {lean: 'true', docker-anonymous: 'true'}", "with: {lean: 'true'}", 1
        )
        with self.assertRaisesRegex(ValueError, "formal-model job"):
            POLICY.validate(unsafe)

    def test_anonymous_docker_cannot_skip_isolation_verification(self) -> None:
        unsafe = SETUP_ACTION.replace(
            "if: inputs.docker-anonymous == 'true' || inputs.docker == 'true'",
            "if: inputs.docker == 'true'",
            1,
        )
        with self.assertRaisesRegex(ValueError, "must accept either Docker input"):
            POLICY.validate_setup(unsafe)

    def test_anonymous_docker_does_not_initialize_risc0(self) -> None:
        unsafe = SETUP_ACTION.replace(
            "    - name: Preflight pinned RISC0 guest builder\n"
            "      if: inputs.docker == 'true'",
            "    - name: Preflight pinned RISC0 guest builder\n"
            "      if: inputs.docker-anonymous == 'true' || inputs.docker == 'true'",
            1,
        )
        with self.assertRaisesRegex(ValueError, "dedicated Docker input"):
            POLICY.validate_setup(unsafe)

    def test_routine_dispatch_defaults_to_changed_files(self) -> None:
        unsafe = WORKFLOW.replace("default: development", "default: full", 1)
        with self.assertRaisesRegex(ValueError, "must default"):
            POLICY.validate(unsafe)

    def test_ready_pr_runs_changed_file_checks(self) -> None:
        unsafe = WORKFLOW.replace(
            "types: [opened, synchronize, reopened, ready_for_review]",
            "types: [opened, synchronize, reopened]",
            1,
        )
        with self.assertRaisesRegex(ValueError, "ready PRs"):
            POLICY.validate(unsafe)

    def test_push_cannot_force_full_qualification(self) -> None:
        unsafe = WORKFLOW.replace(
            'if [[ "$EVENT_NAME" == push && "$REF_TYPE" == tag ]] ||',
            'if [[ "$EVENT_NAME" == push ]] ||\n             [[ "$EVENT_NAME" == workflow_dispatch && "$REQUESTED_QUALIFICATION" == full ]]; then',
            1,
        )
        with self.assertRaisesRegex(ValueError, "pushes must not force"):
            POLICY.validate(unsafe)

    def test_release_tag_keeps_full_qualification(self) -> None:
        unsafe = WORKFLOW.replace('"$REF_TYPE" == tag', '"$REF_TYPE" == branch', 1)
        with self.assertRaisesRegex(ValueError, "release tag pushes"):
            POLICY.validate(unsafe)

    def test_each_mandatory_command_fails_closed_when_removed(self) -> None:
        for command in POLICY.MANDATORY_COMMANDS:
            with self.subTest(command=command), self.assertRaises(ValueError):
                POLICY.validate(WORKFLOW.replace(command, "removed-command", 1))

    def test_missing_stage_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing mandatory job: kani"):
            POLICY.validate(WORKFLOW.replace("  kani:\n", "  removed-kani:\n", 1))

    def test_formal_proofs_and_conformance_remain_independently_mandatory(self) -> None:
        for job in ("formal-models", "formal-conformance"):
            with self.subTest(job=job), self.assertRaisesRegex(
                ValueError, f"missing mandatory job: {job}"
            ):
                POLICY.validate(WORKFLOW.replace(f"  {job}:\n", f"  removed-{job}:\n", 1))

    def test_incomplete_aggregate_dependency_set_fails_closed(self) -> None:
        incomplete = WORKFLOW.replace(", vectors]", "]", 1)
        with self.assertRaisesRegex(ValueError, "complete stage set"):
            POLICY.validate(incomplete)

    def test_missing_push_reachability_guard_fails_closed(self) -> None:
        unsafe = WORKFLOW.replace('git cat-file -e "${BEFORE_SHA}^{commit}"', "true", 1)
        with self.assertRaisesRegex(ValueError, "before SHA is reachable"):
            POLICY.validate(unsafe)

    def test_missing_pr_merge_base_diff_fails_closed(self) -> None:
        unsafe = WORKFLOW.replace(
            'changed=$(git diff --name-only "origin/${BASE_REF}...HEAD")',
            "changed='docs/example.md'",
            1,
        )
        with self.assertRaisesRegex(ValueError, "effective diff"):
            POLICY.validate(unsafe)

    def test_draft_lightweight_guard_fails_closed_when_removed(self) -> None:
        unsafe = WORKFLOW.replace(
            '"$EVENT_NAME" == pull_request && "$PR_DRAFT" == true',
            '"$PR_DRAFT" == false',
            1,
        )
        with self.assertRaisesRegex(ValueError, "draft PR events"):
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

    def test_ci_workflow_change_uses_only_policy_job(self) -> None:
        scope = self.classify(False, ".github/workflows/kernel.yml")
        self.assertEqual({value for key, value in scope.items() if key != "full"}, {"false"})

    def test_ios_packaging_change_selects_apple_only(self) -> None:
        scope = self.classify(
            False,
            "mobile/ios/ActiveChainWalletApp/project.yml",
            "vendor/AnyIdentity/Artifacts/CAnyIdentity.xcframework/Info.plist",
            "scripts/build-anyidentity.sh",
            "scripts/check-ios-wallet-archive.py",
        )
        self.assertEqual(scope["apple"], "true")
        self.assertEqual(
            {value for key, value in scope.items() if key not in ("full", "apple")},
            {"false"},
        )

    def test_full_qualification_selects_every_stage(self) -> None:
        scope = self.classify(True, "docs/example.md")
        self.assertEqual(set(scope.values()), {"true"})

    def test_kanalen_probe_change_selects_runtime(self) -> None:
        scope = self.classify(False, "scripts/test_probe_kanalen_rpc.py")
        self.assertEqual(scope["runtime"], "true")


if __name__ == "__main__":
    unittest.main()
