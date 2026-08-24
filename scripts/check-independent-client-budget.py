#!/usr/bin/env python3
"""Check the P-134 per-version client budget against the canonical tag registry."""

from __future__ import annotations

import csv
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "testing" / "type-tag-registry-v1.tsv"
BUDGET = ROOT / "testing" / "independent-client-budget-v1.tsv"


def registry_tags() -> set[int]:
    tags: set[int] = set()
    for raw in REGISTRY.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("\t")
        if len(fields) != 4:
            raise ValueError(f"malformed registry row: {raw}")
        tags.add(int(fields[0], 16))
    return tags


def main() -> int:
    tags = registry_tags()
    # Application-only records are deliberately outside the consensus verifier surface even
    # when present in the global canonical registry. P-133 owns escrow/attestation records;
    # G8.1 owns finalized-evidence settlement/accounting records whose state commitment is
    # anchored through the existing consensus surface rather than interpreted by validators.
    application_only = set(range(0x0146, 0x0149)) | set(range(0x01CA, 0x01D3))
    normative_tags = tags - application_only
    private = set(range(0x00A0, 0x00AC))
    protected = set(range(0x00AC, 0x00BA))
    compute_jobs = set(range(0x00C3, 0x00C6))
    expected = [
        len(normative_tags - private - protected - compute_jobs),
        len(normative_tags - private - protected - compute_jobs),
        len(normative_tags - protected - compute_jobs),
        len(normative_tags - compute_jobs),
        len(normative_tags),
        len(normative_tags),
    ]

    with BUDGET.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
    if [int(row["revision"]) for row in rows] != list(range(1, 7)):
        raise ValueError("budget revisions must be the exact ordered sequence 1..=6")
    actual = [int(row["active_type_identities"]) for row in rows]
    if actual != expected:
        raise ValueError(f"stale active-type budget: expected {expected}, got {actual}")
    increments = [actual[0], *[right - left for left, right in zip(actual, actual[1:])]]
    published_increments = [int(row["newly_active_identities"]) for row in rows]
    if increments != published_increments:
        raise ValueError(
            f"stale incremental budget: expected {increments}, got {published_increments}"
        )
    if any(not row["incremental_engineer_months"] or not row["gate"] for row in rows):
        raise ValueError("every version requires an engineering estimate and named gate")
    print(
        f"independent-client budget verified: {len(normative_tags)} normative identities, "
        f"v1.0 active={actual[0]}, revisions={len(rows)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
