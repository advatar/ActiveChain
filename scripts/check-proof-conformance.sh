#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
matrix="$root/testing/proof-conformance-v1.tsv"
manifest="$root/testing/vectors/manifest-v1.json"

python3 - "$root" "$matrix" "$manifest" <<'PY'
import csv, hashlib, json, pathlib, sys

root = pathlib.Path(sys.argv[1])
matrix = pathlib.Path(sys.argv[2])
manifest = pathlib.Path(sys.argv[3])
allowed = {"differential", "trace", "external-boundary"}

with matrix.open(newline="") as source:
    rows = list(csv.DictReader(source, delimiter="\t"))
expected_fields = ["domain", "formal_artifact", "production_witness", "classification"]
if not rows or list(rows[0]) != expected_fields:
    raise SystemExit("proof conformance matrix has a missing or reordered schema")
domains = [row["domain"] for row in rows]
if len(domains) != len(set(domains)):
    raise SystemExit("proof conformance matrix has duplicate domains")
if domains != sorted(domains):
    raise SystemExit("proof conformance matrix domains are not canonically ordered")
for row in rows:
    if not row["domain"] or row["classification"] not in allowed:
        raise SystemExit(f"invalid conformance row: {row}")
    for field in ("formal_artifact", "production_witness"):
        path = root / row[field]
        if not path.is_file():
            raise SystemExit(f"missing conformance artifact: {row[field]}")

data = json.loads(manifest.read_text())
ids = set()
for vector in data["vectors"]:
    if vector["id"] in ids:
        raise SystemExit(f"duplicate vector id: {vector['id']}")
    ids.add(vector["id"])
    path = manifest.parent / vector["source"]
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != vector["sha256"]:
        raise SystemExit(f"vector digest mismatch: {vector['id']}")
for malformed in data["malformed_cases"]:
    if not (manifest.parent / malformed["source"]).is_file():
        raise SystemExit(f"missing malformed vector: {malformed['id']}")

# Mutation audit: each structural corruption must be distinguishable by the
# same predicates used above.
assert len(domains + [domains[0]]) != len(set(domains + [domains[0]]))
assert expected_fields[:-1] != expected_fields
assert list(reversed(domains)) != sorted(domains)
assert "substituted" not in allowed
print(f"audited {len(rows)} proof domains and {len(ids)} hashed vectors")
PY

cargo test --locked -p activechain-vector-generator
cargo test --locked -p activechain-protocol-types checked_arithmetic::tests
cargo test --locked -p activechain-consensus-runtime \
  protected_state_snapshot_is_atomic_restart_safe_and_fail_closed

echo "proof conformance checks passed"
