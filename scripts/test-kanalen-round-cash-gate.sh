#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/activechain-kanalen-cash-gate.XXXXXX")
trap 'rm -rf "$test_root"' EXIT

deployment_root="$test_root/deployment"
binary_root="$deployment_root/current/bin"
state_root="$deployment_root/chain"
rpc_root="$deployment_root/rpc"
fake_path="$test_root/bin"
mkdir -p "$binary_root" "$state_root/keys" "$rpc_root" "$fake_path"
printf 'ACTIVECHAIN_CHAIN_ID_HEX=00\n' > "$deployment_root/network.env"
: > "$state_root/genesis.bin"
: > "$state_root/keys/validator-0.key"
: > "$rpc_root/rpc-index.snapshot"

cp "$repo_root/deploy/kanalen/scripts/run-kanalen-round.sh" "$test_root/run-kanalen-round.sh"
chmod +x "$test_root/run-kanalen-round.sh"

for command in nc validator-node; do
  printf '#!/bin/sh\nexit 0\n' > "$fake_path/$command"
  chmod +x "$fake_path/$command"
done
cp "$fake_path/validator-node" "$binary_root/validator-node"

cat > "$binary_root/activechain-rpc-ingest" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$ACTIVECHAIN_INGEST_ARGUMENTS"
EOF
chmod +x "$binary_root/activechain-rpc-ingest"

run_round() {
  ACTIVECHAIN_KANALEN_ROOT="$deployment_root" \
    ACTIVECHAIN_INGEST_ARGUMENTS="$test_root/ingest-arguments" \
    PATH="$fake_path:$PATH" \
    "$test_root/run-kanalen-round.sh"
}

if run_round >"$test_root/missing-cash.out" 2>&1; then
  echo "round unexpectedly published metadata without finalized cash" >&2
  exit 1
fi
grep -q 'refusing metadata-only RPC publication' "$test_root/missing-cash.out"

: > "$state_root/finalized-cash.snapshot"
if run_round >"$test_root/missing-finality.out" 2>&1; then
  echo "round unexpectedly published cash without finality evidence" >&2
  exit 1
fi
grep -q 'refusing unauthenticated RPC publication' "$test_root/missing-finality.out"

: > "$state_root/finality.bundle"
run_round
test "$(sed -n '1p' "$test_root/ingest-arguments")" = "$state_root/validator-0.snapshot"
test "$(sed -n '2p' "$test_root/ingest-arguments")" = "$rpc_root/rpc-index.snapshot"
test "$(sed -n '3p' "$test_root/ingest-arguments")" = "$state_root/finalized-cash.snapshot"
test "$(sed -n '4p' "$test_root/ingest-arguments")" = "$state_root/finality.bundle"
test "$(wc -l < "$test_root/ingest-arguments" | tr -d ' ')" = 4

echo "Kanalen finalized-cash publication gate passed"
