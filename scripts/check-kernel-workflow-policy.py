#!/usr/bin/env python3
"""Fail closed if deterministic-kernel qualification loses a mandatory stage or command."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKFLOW = ROOT / ".github" / "workflows" / "kernel.yml"
DEFAULT_SETUP_ACTION = ROOT / ".github" / "actions" / "kernel-setup" / "action.yml"

MANDATORY_JOBS = (
    "policy",
    "static",
    "formal-models",
    "formal-conformance",
    "kani",
    "tests",
    "apple",
    "runtime",
    "vectors",
)

MANDATORY_COMMANDS = (
    "cargo fmt --all --check",
    "python3 scripts/check-type-tag-registry.py",
    "python3 scripts/check-independent-client-budget.py",
    'bash scripts/classify-kernel-change-scope.sh "$full"',
    "go test ./...",
    "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
    "cargo check --locked --target aarch64-apple-ios --lib",
    "lake build",
    "bash scripts/check-formal-models.sh",
    "bash scripts/check-kani-codec.sh",
    "bash scripts/check-kani-verifier-ffi.sh",
    "bash scripts/check-kani-object-vm.sh",
    "bash scripts/check-kani-protocol-types.sh",
    "bash scripts/check-kani-commitment.sh",
    "formal/verus/verify.sh",
    "bash scripts/check-proof-conformance.sh",
    "cargo test --locked --workspace --all-features",
    "cargo test --locked --workspace --doc",
    "cargo build --locked --workspace --release",
    'bash scripts/check-apple-reproducibility.sh "$GITHUB_SHA"',
    "cargo test --locked --workspace --release",
    "bash scripts/rehearse-validator-processes.sh",
    "bash scripts/rehearse-live-process-quorum.sh",
    "bash scripts/rehearse-consensus-view-change.sh",
    "bash scripts/rehearse-validator-key-rotation.sh",
    "bash scripts/test-kanalen-round-cash-gate.sh",
    "bash scripts/test-qualify-kanalen-local.sh",
    "python3 scripts/test_probe_kanalen_rpc.py",
)


def validate(text: str) -> None:
    errors: list[str] = []
    if "workflow_dispatch:" not in text or "qualification:" not in text:
        errors.append("workflow_dispatch must expose an explicit qualification input")
    if "branches: [main]" in text:
        errors.append("main merges must not repeat an already-qualified full candidate gate")
    if "CARGO_TARGET_DIR: /Users/johansellstrom/.cache/activechain-ci/target/${{ github.sha }}" not in text:
        errors.append("Cargo artifacts must be isolated by exact qualified SHA")
    for job in MANDATORY_JOBS:
        if not re.search(rf"^  {re.escape(job)}:\s*$", text, re.MULTILINE):
            errors.append(f"missing mandatory job: {job}")
    required_needs = "needs: [scope, policy, static, formal-models, formal-conformance, kani, tests, apple, runtime, vectors]"
    if text.count(required_needs) != 2:
        errors.append("both aggregate jobs must name the complete stage set")
    if "if: always() && needs.scope.outputs.full == 'true'" not in text:
        errors.append("full aggregate must be fail-closed and full-scope-only")
    if '"$PR_ACTION" == synchronize' not in text or 'git diff --name-only "$BEFORE_SHA...HEAD"' not in text:
        errors.append("PR synchronization must classify only the newly pushed commit delta")
    if text.count('git cat-file -e "${BEFORE_SHA}^{commit}"') != 2:
        errors.append("incremental classification must prove the before SHA is reachable")
    if "before SHA is unreachable after force-push; classifying complete PR diff" not in text:
        errors.append("force-push classification must conservatively fall back to the PR-base diff")
    if (
        "PR_DRAFT: ${{ github.event.pull_request.draft }}" not in text
        or '"$PR_DRAFT" == true || "$PR_ACTION" == ready_for_review' not in text
        or "draft/review-bookkeeping event: selecting lightweight policy-only checks" not in text
    ):
        errors.append("draft and ready-for-review bookkeeping must remain policy-only")
    if text.count("git status --porcelain --untracked-files=normal") != 2:
        errors.append("Apple qualification must prove cleanliness before and after header generation")
    if text.count("with: {lean: 'true', docker-anonymous: 'true'}") != 1:
        errors.append("formal-model job must request Lean and anonymous Docker isolation")
    for command in MANDATORY_COMMANDS:
        count = text.count(command)
        if count != 1:
            errors.append(f"mandatory command must occur exactly once ({count}): {command}")
    if errors:
        raise ValueError("\n".join(errors))


def validate_setup(text: str) -> None:
    errors: list[str] = []
    anonymous_condition = "if: inputs.docker-anonymous == 'true' || inputs.docker == 'true'"
    if not re.search(
        r"^  docker-anonymous:\n"
        r"    description: Configure isolated anonymous Docker authentication\n"
        r"    default: 'false'$",
        text,
        re.MULTILINE,
    ):
        errors.append("kernel setup must expose disabled-by-default anonymous Docker isolation")
    if text.count(anonymous_condition) != 2:
        errors.append("Docker isolation and its verification must accept either Docker input")
    preflight = text.partition("    - name: Preflight pinned RISC0 guest builder")[2]
    if not preflight or not re.search(
        r"^      if: inputs\.docker == 'true'$", preflight, re.MULTILINE
    ):
        errors.append("RISC0 setup must remain gated by the dedicated Docker input")
    if "docker-anonymous" in preflight:
        errors.append("anonymous Docker isolation must not initialize the RISC0 builder")
    if '"credsStore":"activechain-anonymous"' not in text:
        errors.append("anonymous Docker isolation must not consult host credential helpers")
    if errors:
        raise ValueError("\n".join(errors))


def main() -> int:
    workflow = Path(sys.argv[1]) if len(sys.argv) == 2 else DEFAULT_WORKFLOW
    validate(workflow.read_text(encoding="utf-8"))
    validate_setup(DEFAULT_SETUP_ACTION.read_text(encoding="utf-8"))
    print(f"kernel workflow policy verified: {len(MANDATORY_JOBS)} resumable stages")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
