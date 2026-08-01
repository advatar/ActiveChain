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

# The exact ledger produced by reset must feed both the first and restarted publication rounds.
# Only derived cash/finality artifacts are removed between rounds.
mkdir -p "$deployment/current/scripts" "$deployment/rpc" "$test_root/bin"
cp "$repo_root/deploy/kanalen/scripts/run-kanalen-round.sh" \
  "$deployment/current/scripts/run-kanalen-round.sh"
chmod +x "$deployment/current/scripts/run-kanalen-round.sh"
: > "$deployment/rpc/rpc-index.snapshot"
printf '#!/bin/sh\nexit 0\n' > "$test_root/bin/nc"
chmod +x "$test_root/bin/nc"

cat > "$deployment/current/bin/validator-node" <<'EOF'
#!/bin/sh
count=0
test ! -f "$ACTIVECHAIN_ROUND_COUNT" || count=$(cat "$ACTIVECHAIN_ROUND_COUNT")
count=$((count + 1))
printf '%s\n' "$count" > "$ACTIVECHAIN_ROUND_COUNT"
printf '%s\n' "round=$count" >> "$ACTIVECHAIN_VALIDATOR_ARGUMENTS"
for argument in "$@"; do
  printf '%s\n' "$argument" >> "$ACTIVECHAIN_VALIDATOR_ARGUMENTS"
  case "$argument" in
    --finalized-cash-out=*) printf 'cash-round-%s\n' "$count" > "${argument#*=}" ;;
    --finality-out=*) printf 'finality-round-%s\n' "$count" > "${argument#*=}" ;;
  esac
done
EOF
chmod +x "$deployment/current/bin/validator-node"

cat > "$deployment/current/bin/activechain-rpc-ingest" <<'EOF'
#!/bin/sh
printf '%s\n' 'ingest' >> "$ACTIVECHAIN_INGEST_ARGUMENTS"
printf '%s\n' "$@" >> "$ACTIVECHAIN_INGEST_ARGUMENTS"
EOF
chmod +x "$deployment/current/bin/activechain-rpc-ingest"

ledger_checksum=$(cksum "$deployment/chain/cash-ledger.snapshot")
run_round() {
  ACTIVECHAIN_KANALEN_ROOT="$deployment" \
  ACTIVECHAIN_ROUND_COUNT="$test_root/round-count" \
  ACTIVECHAIN_VALIDATOR_ARGUMENTS="$test_root/validator-arguments" \
  ACTIVECHAIN_INGEST_ARGUMENTS="$test_root/ingest-arguments" \
  PATH="$test_root/bin:$PATH" \
    "$deployment/current/scripts/run-kanalen-round.sh"
}

run_round
test "$(cat "$test_root/round-count")" = 1
grep -q '^cash-round-1$' "$deployment/chain/finalized-cash.snapshot"
grep -q '^finality-round-1$' "$deployment/chain/finality.bundle"
test "$(cksum "$deployment/chain/cash-ledger.snapshot")" = "$ledger_checksum"

rm "$deployment/chain/finalized-cash.snapshot" "$deployment/chain/finality.bundle"
run_round
test "$(cat "$test_root/round-count")" = 2
grep -q '^cash-round-2$' "$deployment/chain/finalized-cash.snapshot"
grep -q '^finality-round-2$' "$deployment/chain/finality.bundle"
test "$(cksum "$deployment/chain/cash-ledger.snapshot")" = "$ledger_checksum"
test "$(grep -c '^ingest$' "$test_root/ingest-arguments")" = 2
test "$(grep -c "^$deployment/chain/cash-ledger.snapshot$" \
  "$test_root/validator-arguments")" = 0
test "$(grep -c "^--cash-ledger=$deployment/chain/cash-ledger.snapshot$" \
  "$test_root/validator-arguments")" = 2

echo "Kanalen cash reset provisioning gate passed"
