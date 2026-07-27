#!/usr/bin/env python3
"""Minimal implementation-independent v1 conformance harness.

This deliberately consumes only the published TSV contract.  It does not import
ActiveChain Rust crates, so it can be used as a second-client smoke gate before
an independent cryptographic implementation is integrated.
"""

from pathlib import Path
import csv
import sys


REQUIRED = {
    "canonical_codec": "accept",
    "trailing_bytes": "reject",
    "unknown_feature": "reject",
    "alternate_impl": "accept",
    "rust_private_api": "reject",
    "malformed_order": "reject",
}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    vector_path = root / "testing" / "vectors" / "independent-client-conformance-v1.tsv"
    with vector_path.open(newline="", encoding="utf-8") as handle:
        raw = handle.read()
    # The repository fixture is intentionally plain text and historically used
    # escaped ``\\t`` separators; accept either spelling while remaining strict
    # about the required columns.
    if "\t" not in raw.splitlines()[0]:
        raw = raw.replace(r"\t", "\t")
    rows = list(csv.DictReader(raw.splitlines(), delimiter="\t"))

    by_case = {row["case"]: row for row in rows}
    missing = sorted(set(REQUIRED) - set(by_case))
    if missing:
        print(f"missing conformance cases: {', '.join(missing)}", file=sys.stderr)
        return 1
    malformed = [
        case
        for case, expected in REQUIRED.items()
        if by_case[case]["expected"] != expected
        or not by_case[case]["client_behavior"]
        or not by_case[case]["reason"]
    ]
    if malformed:
        print(f"invalid conformance rows: {', '.join(malformed)}", file=sys.stderr)
        return 1
    print(f"independent-client conformance: {len(rows)} published cases verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
