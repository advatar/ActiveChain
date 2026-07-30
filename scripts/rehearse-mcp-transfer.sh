#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rehearsal_root=$(mktemp -d "${TMPDIR:-/tmp}/activechain-mcp-transfer.XXXXXX")
cleanup() {
  if [[ -n "${rehearsal_root:-}" && -d "$rehearsal_root" ]]; then
    rm -r -- "$rehearsal_root"
  fi
}
trap cleanup EXIT

cd "$repo_root"
cargo run --quiet -p activechain-mcp-rehearsal -- "$rehearsal_root/state" \
  > "$rehearsal_root/report.json"

python3 - "$rehearsal_root/report.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)

required_states = {"pending", "denied", "expired", "submitted", "finalized", "failed"}
assert report["status"] == "passed"
assert report["developmental_unaudited"] is True
assert report["validator_count"] == 3
assert report["independently_verified"] is True
assert report["idempotent_reconnect"] is True
assert report["secrets_persisted"] is False
assert required_states <= set(report["states"])
for field in (
    "mcp_request_id",
    "proposal_id",
    "intent_commitment",
    "authorization_commitment",
    "transaction_id",
    "receipt_commitment",
):
    assert report[field]

print(json.dumps(report, indent=2, sort_keys=True))
PY
