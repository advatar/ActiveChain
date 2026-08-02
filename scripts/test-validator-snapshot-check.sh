#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workdir=$(mktemp -d "${TMPDIR:-/tmp}/activechain-snapshot-check.XXXXXX")
trap 'rm -rf "$workdir"' EXIT

snapshot="$workdir/validator.snapshot"
indexer="$workdir/indexer-tool"
touch "$snapshot"

cat > "$indexer" <<'EOF'
#!/usr/bin/env bash
printf '{"snapshot_schema_version":%s,"genesis_commitment":"%s"}\n' \
  "${FAKE_SNAPSHOT_SCHEMA:?}" "${FAKE_GENESIS:?}"
EOF
chmod 755 "$indexer"

FAKE_SNAPSHOT_SCHEMA=6 FAKE_GENESIS=abcd \
  "$repo_root/scripts/check-validator-snapshot.sh" "$snapshot" "$indexer"

if FAKE_SNAPSHOT_SCHEMA=5 FAKE_GENESIS=abcd \
  "$repo_root/scripts/check-validator-snapshot.sh" "$snapshot" "$indexer"; then
  echo "schema 5 unexpectedly passed the schema 6 default" >&2
  exit 1
fi

ACTIVECHAIN_EXPECTED_SNAPSHOT_SCHEMA_VERSION=5 \
FAKE_SNAPSHOT_SCHEMA=5 FAKE_GENESIS=abcd \
  "$repo_root/scripts/check-validator-snapshot.sh" "$snapshot" "$indexer"

if ACTIVECHAIN_EXPECTED_GENESIS_COMMITMENT=dcba \
  FAKE_SNAPSHOT_SCHEMA=6 FAKE_GENESIS=abcd \
  "$repo_root/scripts/check-validator-snapshot.sh" "$snapshot" "$indexer"; then
  echo "genesis mismatch unexpectedly passed" >&2
  exit 1
fi

echo "validator snapshot preflight tests passed"
