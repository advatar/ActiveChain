#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/activechain-kanalen-cash-reset.XXXXXX")
trap 'rm -rf "$test_root"' EXIT
deployment="$test_root/deployment"
mkdir -p "$deployment/current/bin" "$deployment/chain" "$deployment/rpc"
cp "$repo_root/deploy/kanalen/network.env" "$deployment/current/network.env"
printf 'old cash\n' > "$deployment/chain/cash-ledger.snapshot"

cat > "$deployment/current/bin/genesis-tool" <<'EOF'
#!/bin/sh
output=$1
keys=$5
mkdir -p "$keys"
: > "$output"
: > "$keys/validator-0.key"
printf 'genesis_commitment=%096d\n' 1
EOF
chmod +x "$deployment/current/bin/genesis-tool"

cat > "$deployment/current/bin/cash-genesis-tool" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$ACTIVECHAIN_CASH_TOOL_ARGUMENTS"
printf 'canonical cash\n' > "$1"
EOF
chmod +x "$deployment/current/bin/cash-genesis-tool"

ACTIVECHAIN_KANALEN_ROOT="$deployment" \
ACTIVECHAIN_CASH_GENESIS_OWNER_HEX="$(printf '11%.0s' $(seq 1 48))" \
ACTIVECHAIN_CASH_TOOL_ARGUMENTS="$test_root/cash-arguments" \
  "$repo_root/deploy/kanalen/scripts/reset-kanalen-state.sh" --confirm

test -s "$deployment/chain/cash-ledger.snapshot"
test "$(sed -n '1p' "$test_root/cash-arguments")" = "$deployment/chain/cash-ledger.snapshot"
test "$(sed -n '2p' "$test_root/cash-arguments")" = "b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0b095e6cfe944bd2c9f6535b4c927782f1"
test "$(sed -n '4p' "$test_root/cash-arguments")" = "1000000000000000000000000000"
test "$(sed -n '5p' "$test_root/cash-arguments")" = "100000000000000000000000000"
find "$deployment" -path '*/chain/cash-ledger.snapshot' -not -path "$deployment/chain/cash-ledger.snapshot" |
  grep -q .

echo "Kanalen cash reset provisioning gate passed"
