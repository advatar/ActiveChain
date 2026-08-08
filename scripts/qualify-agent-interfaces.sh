#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

cargo test \
  -p activechain-agent-interfaces \
  -p activechain-proposal-gateway \
  -p activechain-mcp-server \
  -p activechain-a2ui-renderer \
  -p activechain-wallet-ffi \
  -p activechain-mcp-rehearsal

python3 - <<'PY'
import json
from pathlib import Path

root = Path.cwd()
mcp = json.loads((root / "testing/vectors/mcp-read-only-v1.json").read_text())
components = json.loads(
    (root / "testing/vectors/a2ui-transfer-review-components.json").read_text()
)
data = json.loads((root / "testing/vectors/a2ui-transfer-review-datamodel.json").read_text())
policy = (root / "docs/AGENT_INTERFACE_QUALIFICATION_V1.md").read_text()

assert mcp["protocol_version"] == "2025-11-25"
assert mcp["limits"]["maximum_frame_bytes"] == 262144
assert components["version"] == data["version"] == "v0.9"
assert components["updateComponents"]["surfaceId"] == data["updateDataModel"]["surfaceId"]
for required in (
    "developmental and externally unaudited",
    "Incident disable procedure",
    "Privacy and telemetry",
    "External audit scope",
    "Compatibility matrix",
):
    assert required in policy

print("agent-interface qualification: passed")
PY

python3 scripts/test-actum-agent-plugin.py
