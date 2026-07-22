#!/usr/bin/env python3
"""Audit published proof scopes against the canonical conformance inventory."""

import csv
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]


def rows(path: pathlib.Path):
    with path.open(newline="") as source:
        return list(csv.DictReader(source, delimiter="\t"))


conformance = rows(root / "testing/proof-conformance-v1.tsv")
scopes = rows(root / "formal/proof-scope-index-v1.tsv")
expected_fields = ["domain", "scope", "assumptions", "boundary", "counterexample_policy"]
if not scopes or list(scopes[0]) != expected_fields:
    raise SystemExit("proof scope index schema is missing or reordered")
domains = [row["domain"] for row in scopes]
if domains != sorted(domains) or len(domains) != len(set(domains)):
    raise SystemExit("proof scope domains must be unique and canonically ordered")
expected = [row["domain"] for row in conformance]
if domains != expected:
    raise SystemExit(f"proof scope coverage mismatch: expected={expected}, actual={domains}")
policies = {"retain-minimize-fix-claim", "timeout-explicit-unproved", "external-assumption"}
scope_text = ""
for row in scopes:
    if not row["assumptions"] or not row["boundary"] or row["counterexample_policy"] not in policies:
        raise SystemExit(f"incomplete proof scope record: {row['domain']}")
    path = root / row["scope"]
    if not path.is_file():
        raise SystemExit(f"missing proof scope: {row['scope']}")
    scope_text += path.read_text() + "\n"
for unproved_file in sorted((root / "formal/tamarin").glob("*.unproved")):
    for target in (line.strip() for line in unproved_file.read_text().splitlines()):
        if target and target not in scope_text:
            raise SystemExit(f"unpublished unproved target: {target}")

# Structural mutation audit.
assert domains + [domains[0]] != sorted(set(domains))
assert "" not in {row["assumptions"] for row in scopes}
assert "unknown-policy" not in policies
print(f"published proof scopes for {len(scopes)} domains")
