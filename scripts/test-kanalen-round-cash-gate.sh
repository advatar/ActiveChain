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
printf 'ACTIVECHAIN_CHAIN_ID_HEX=%096d\n' 0 > "$deployment_root/network.env"
: > "$state_root/genesis.bin"
for validator in 0 1 2; do
  : > "$state_root/keys/validator-$validator.key"
  : > "$state_root/validator-$validator.snapshot"
done
: > "$state_root/cash-ledger.snapshot"
: > "$state_root/pending-cash-actions.batch"
: > "$rpc_root/rpc-index.snapshot"

cp "$repo_root/deploy/kanalen/scripts/run-kanalen-round.sh" "$test_root/run-kanalen-round.sh"
chmod +x "$test_root/run-kanalen-round.sh"

printf '#!/bin/sh\nexit 0\n' > "$fake_path/nc"
chmod +x "$fake_path/nc"
printf '#!/bin/sh\nexit 0\n' > "$fake_path/launchctl"
chmod +x "$fake_path/launchctl"
cat > "$binary_root/validator-node" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$ACTIVECHAIN_VALIDATOR_ARGUMENTS"
for argument in "$@"; do
  case "$argument" in
    --finalized-cash-out=*) : > "${argument#*=}" ;;
    --finality-out=*) : > "${argument#*=}" ;;
  esac
done
EOF
chmod +x "$binary_root/validator-node"

cat > "$binary_root/activechain-rpc-ingest" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$ACTIVECHAIN_INGEST_ARGUMENTS"
EOF
chmod +x "$binary_root/activechain-rpc-ingest"

cat > "$binary_root/activechain-transfer-spool" <<'EOF'
#!/bin/sh
case "$1" in
  prepare)
    printf '%s\n' "$@" > "$ACTIVECHAIN_TRANSFER_PREPARE_ARGUMENTS"
    printf '\000\000\000\001\001' > "$5"
    ;;
  reconcile-latest)
    printf '%s\n' "$@" > "$ACTIVECHAIN_TRANSFER_RECONCILE_ARGUMENTS"
    ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$binary_root/activechain-transfer-spool"

run_round() {
  ACTIVECHAIN_KANALEN_ROOT="$deployment_root" \
  ACTIVECHAIN_INGEST_ARGUMENTS="$test_root/ingest-arguments" \
    ACTIVECHAIN_VALIDATOR_ARGUMENTS="$test_root/validator-arguments" \
    ACTIVECHAIN_TRANSFER_PREPARE_ARGUMENTS="$test_root/transfer-prepare-arguments" \
    ACTIVECHAIN_TRANSFER_RECONCILE_ARGUMENTS="$test_root/transfer-reconcile-arguments" \
    PATH="$fake_path:$PATH" \
    "$test_root/run-kanalen-round.sh"
}

rm -f "$state_root/finalized-cash.snapshot" "$state_root/finality.bundle"
cat > "$binary_root/validator-node" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$binary_root/validator-node"
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
rm -f "$state_root/pending-cash-actions.batch"
: > "$rpc_root/transfers.snapshot"
cat > "$binary_root/validator-node" <<'EOF'
#!/bin/sh
test "$5" != 0 || exit 1
printf '%s\n' "$@" > "$ACTIVECHAIN_VALIDATOR_ARGUMENTS"
for argument in "$@"; do
  case "$argument" in
    --finalized-cash-out=*) : > "${argument#*=}" ;;
    --finality-out=*) : > "${argument#*=}" ;;
  esac
done
EOF
chmod +x "$binary_root/validator-node"
run_round
test "$(sed -n '1p' "$test_root/ingest-arguments")" = "$state_root/validator-1.snapshot"
test "$(sed -n '2p' "$test_root/ingest-arguments")" = "$rpc_root/rpc-index.snapshot"
test "$(sed -n '3p' "$test_root/ingest-arguments")" = "$state_root/finalized-cash.snapshot"
test "$(sed -n '4p' "$test_root/ingest-arguments")" = "$state_root/finality.bundle"
test "$(sed -n '5p' "$test_root/ingest-arguments")" = "$state_root/execution.snapshot"
test "$(wc -l < "$test_root/ingest-arguments" | tr -d ' ')" = 5
grep -q '^--chain-id-hex=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000$' "$test_root/validator-arguments"
grep -q "^--finalized-cash-out=$state_root/finalized-cash.snapshot$" "$test_root/validator-arguments"
grep -q "^--finality-out=$state_root/finality.bundle$" "$test_root/validator-arguments"
grep -q "^--cash-ledger=$state_root/cash-ledger.snapshot$" "$test_root/validator-arguments"
grep -q "^--cash-actions=$state_root/pending-cash-actions.batch$" "$test_root/validator-arguments"
grep -q '^--peer=1@127.0.0.1:49153$' "$test_root/validator-arguments"
grep -q '^--peer=3@127.0.0.1:49155$' "$test_root/validator-arguments"
test "$(sed -n '1p' "$test_root/transfer-prepare-arguments")" = prepare
test "$(sed -n '2p' "$test_root/transfer-prepare-arguments")" = "$rpc_root/transfers.snapshot"
test "$(sed -n '5p' "$test_root/transfer-prepare-arguments")" = "$state_root/pending-cash-actions.batch"
test "$(sed -n '1p' "$test_root/transfer-reconcile-arguments")" = reconcile-latest
test "$(sed -n '2p' "$test_root/transfer-reconcile-arguments")" = "$rpc_root/transfers.snapshot"
test "$(sed -n '4p' "$test_root/transfer-reconcile-arguments")" = "$state_root"

echo "Kanalen finalized-cash publication gate passed"
