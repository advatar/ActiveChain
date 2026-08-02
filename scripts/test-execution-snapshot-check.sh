#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workdir=$(mktemp -d "${TMPDIR:-/tmp}/activechain-execution-check.XXXXXX")
trap 'rm -rf "$workdir"' EXIT
snapshot="$workdir/execution.snapshot"
indexer="$workdir/indexer-tool"
touch "$snapshot"

cat > "$indexer" <<'EOF'
#!/usr/bin/env bash
test "$1" = --execution
printf '{"target_schema_version":%s,"chain_id":"%s","height":%s}\n' \
  "${FAKE_TARGET_SCHEMA:?}" "${FAKE_CHAIN:?}" "${FAKE_HEIGHT:?}"
EOF
chmod 755 "$indexer"

ACTIVECHAIN_EXPECTED_CHAIN_ID=abcd ACTIVECHAIN_EXPECTED_EXECUTION_HEIGHT=42 \
FAKE_TARGET_SCHEMA=5 FAKE_CHAIN=abcd FAKE_HEIGHT=42 \
  "$repo_root/scripts/check-execution-snapshot.sh" "$snapshot" "$indexer"

if ACTIVECHAIN_EXPECTED_EXECUTION_SCHEMA_VERSION=4 \
  FAKE_TARGET_SCHEMA=5 FAKE_CHAIN=abcd FAKE_HEIGHT=42 \
  "$repo_root/scripts/check-execution-snapshot.sh" "$snapshot" "$indexer"; then
  echo "wrong target schema unexpectedly passed" >&2
  exit 1
fi
if ACTIVECHAIN_EXPECTED_CHAIN_ID=dcba \
  FAKE_TARGET_SCHEMA=5 FAKE_CHAIN=abcd FAKE_HEIGHT=42 \
  "$repo_root/scripts/check-execution-snapshot.sh" "$snapshot" "$indexer"; then
  echo "wrong chain unexpectedly passed" >&2
  exit 1
fi
if ACTIVECHAIN_EXPECTED_EXECUTION_HEIGHT=43 \
  FAKE_TARGET_SCHEMA=5 FAKE_CHAIN=abcd FAKE_HEIGHT=42 \
  "$repo_root/scripts/check-execution-snapshot.sh" "$snapshot" "$indexer"; then
  echo "wrong height unexpectedly passed" >&2
  exit 1
fi

echo "execution snapshot preflight tests passed"
