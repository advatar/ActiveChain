#!/usr/bin/env python3
"""Verify that every TLA+ runner and proof-scope record uses one pinned asset."""

from __future__ import annotations

import pathlib
import re
import sys


EXPECTED_ASSET_ID = "538706268"
EXPECTED_SHA256 = "dbcc75552f21978a4846688b8e23be1a6b6c0b3fcee35d78fec2df167958ec94"
RUNNERS = (
    pathlib.Path("scripts/check-tla-consensus.sh"),
    pathlib.Path("scripts/check-tla-proof-pipeline.sh"),
)
PROOF_SCOPES = (
    pathlib.Path("formal/CONSENSUS_TLA_PROOF_SCOPE.md"),
    pathlib.Path("formal/PROOF_PIPELINE_TLA_PROOF_SCOPE.md"),
)


def _single_match(pattern: str, text: str, label: str) -> str:
    matches = re.findall(pattern, text, flags=re.MULTILINE | re.DOTALL)
    if len(matches) != 1:
        raise ValueError(f"{label} must contain exactly one pin, found {len(matches)}")
    return matches[0]


def verify(root: pathlib.Path) -> None:
    for relative in RUNNERS:
        text = (root / relative).read_text(encoding="utf-8")
        asset_id = _single_match(r"^tla_asset_id=([0-9]+)$", text, str(relative))
        sha256 = _single_match(r"^tla_sha256=([0-9a-f]{64})$", text, str(relative))
        if asset_id != EXPECTED_ASSET_ID or sha256 != EXPECTED_SHA256:
            raise ValueError(
                f"{relative} has TLA+ pin {asset_id}/{sha256}, expected "
                f"{EXPECTED_ASSET_ID}/{EXPECTED_SHA256}"
            )

    for relative in PROOF_SCOPES:
        text = (root / relative).read_text(encoding="utf-8")
        asset_id = _single_match(
            r"runner pins immutable GitHub release asset `([0-9]+)`",
            text,
            str(relative),
        )
        sha256 = _single_match(
            r"release asset `[0-9]+`.*?SHA-256\s+`([0-9a-f]{64})`",
            text,
            str(relative),
        )
        if asset_id != EXPECTED_ASSET_ID or sha256 != EXPECTED_SHA256:
            raise ValueError(
                f"{relative} has TLA+ pin {asset_id}/{sha256}, expected "
                f"{EXPECTED_ASSET_ID}/{EXPECTED_SHA256}"
            )


def main() -> int:
    try:
        verify(pathlib.Path(__file__).resolve().parents[1])
    except (OSError, ValueError) as error:
        print(f"TLA+ tool pin check failed: {error}", file=sys.stderr)
        return 1
    print(f"TLA+ tool pin verified: asset {EXPECTED_ASSET_ID}, SHA-256 {EXPECTED_SHA256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
