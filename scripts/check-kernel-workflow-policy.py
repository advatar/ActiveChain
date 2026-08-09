#!/usr/bin/env python3
"""Fail closed if deterministic-kernel qualification loses a mandatory stage or command."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKFLOW = ROOT / ".github" / "workflows" / "kernel.yml"

MANDATORY_JOBS = (
    "policy",
    "static",
    "formal",
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
)


def validate(text: str) -> None:
    errors: list[str] = []
    if "workflow_dispatch:" not in text or "qualification:" not in text:
        errors.append("workflow_dispatch must expose an explicit qualification input")
    if "CARGO_TARGET_DIR: /Users/johansellstrom/.cache/activechain-ci/target/${{ github.sha }}" not in text:
        errors.append("Cargo artifacts must be isolated by exact qualified SHA")
    for job in MANDATORY_JOBS:
        if not re.search(rf"^  {re.escape(job)}:\s*$", text, re.MULTILINE):
            errors.append(f"missing mandatory job: {job}")
    required_needs = "needs: [scope, policy, static, formal, kani, tests, apple, runtime, vectors]"
    if text.count(required_needs) != 2:
        errors.append("both aggregate jobs must name the complete stage set")
    if "if: always() && needs.scope.outputs.full == 'true'" not in text:
        errors.append("full aggregate must be fail-closed and full-scope-only")
    for command in MANDATORY_COMMANDS:
        count = text.count(command)
        if count != 1:
            errors.append(f"mandatory command must occur exactly once ({count}): {command}")
    if errors:
        raise ValueError("\n".join(errors))


def main() -> int:
    workflow = Path(sys.argv[1]) if len(sys.argv) == 2 else DEFAULT_WORKFLOW
    validate(workflow.read_text(encoding="utf-8"))
    print(f"kernel workflow policy verified: {len(MANDATORY_JOBS)} resumable stages")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
