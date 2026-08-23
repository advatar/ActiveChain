#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/activechain-testnet-trust.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT
deployment="$test_root/deployment"
revision="0123456789abcdef0123456789abcdef01234567"
release="$deployment/releases/$revision"
state="$deployment/work-proof"
mkdir -p "$release/bin" "$release/launchagents" "$state" "$test_root/tools"
ln -s "$release" "$deployment/current"

printf 'old trust\n' > "$state/trust.bin"
printf 'old signed bundle\n' > "$state/signed-trust-bundle.bin"
printf 'old signer set\n' > "$state/trust-signer-set.bin"
printf 'private bearer material\n' > "$state/bearer.token"
printf 'candidate signed bundle\n' > "$test_root/candidate-signed.bin"
printf 'candidate signer set\n' > "$test_root/candidate-set.bin"
chmod 0600 "$state"/*.bin "$state/bearer.token" "$test_root"/candidate-*.bin
printf '<plist version="1.0"><dict/></plist>\n' \
  > "$release/launchagents/dev.activechain.kanalen.work-proof.plist"

cat > "$release/bin/actum-work-proof-testnet-trust-bootstrap" <<'BOOTSTRAP'
#!/usr/bin/env bash
set -euo pipefail
output="$1"
usage="$4"
chain="$6"
genesis="$7"
policy="$8"
test "$chain" = "b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0b095e6cfe944bd2c9f6535b4c927782f1"
test "$genesis" = "a836c4d201cda6ba33a01aa48011cf5f4d6acdfd1ec409d322dc1b56ed3552a25dcb158e0b1ec0352728653d315d477c"
test "$policy" = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
if [[ -s "$usage" ]]; then
  echo "durable usage is not empty" >&2
  exit 1
fi
printf '%s\n' "$ACTIVECHAIN_TEST_CANDIDATE" > "$output"
BOOTSTRAP
cat > "$release/bin/actum-work-qualification-source" <<'POLICY'
#!/usr/bin/env bash
test "${1:-}" = "--policy-id"
printf '%096d\n' 0 | tr 0 d
POLICY
cat > "$test_root/tools/launchctl" <<'LAUNCHCTL'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$ACTIVECHAIN_LAUNCHCTL_LOG"
if [[ "${1:-}" == "print" ]]; then
  exit 1
fi
LAUNCHCTL
cat > "$test_root/tools/health" <<'HEALTH'
#!/usr/bin/env bash
set -euo pipefail
test -s "$1"
test "$(cat "$ACTIVECHAIN_TEST_TRUST_STORE")" = "$ACTIVECHAIN_EXPECTED_TRUST"
HEALTH
chmod 0755 "$release/bin/actum-work-proof-testnet-trust-bootstrap" \
  "$release/bin/actum-work-qualification-source" \
  "$test_root/tools/launchctl" "$test_root/tools/health"

run_reset() {
  ACTIVECHAIN_KANALEN_ROOT="$deployment" \
  ACTIVECHAIN_LAUNCHCTL="$test_root/tools/launchctl" \
  ACTIVECHAIN_LAUNCHCTL_LOG="$test_root/launchctl.log" \
  ACTIVECHAIN_WORK_PROOF_HEALTH_CHECK="$test_root/tools/health" \
  ACTIVECHAIN_WORK_PROOF_HEALTH_ATTEMPTS=1 \
  ACTIVECHAIN_TEST_TRUST_STORE="$state/trust.bin" \
  ACTIVECHAIN_TEST_CANDIDATE="$1" \
  ACTIVECHAIN_EXPECTED_TRUST="$2" \
    bash "$repo_root/deploy/kanalen/scripts/rebootstrap-testnet-work-proof-trust.sh" \
      "$test_root/candidate-signed.bin" "$test_root/candidate-set.bin" "$revision"
}

run_reset "new trust" "new trust"
test "$(cat "$state/trust.bin")" = "new trust"
test "$(cat "$state/signed-trust-bundle.bin")" = "candidate signed bundle"
test "$(cat "$state/trust-signer-set.bin")" = "candidate signer set"
archive="$(find "$state/trust-archive" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
test "$(cat "$archive/trust.bin")" = "old trust"

if run_reset "unhealthy trust" "never healthy"; then
  echo "unhealthy replacement unexpectedly succeeded" >&2
  exit 1
fi
test "$(cat "$state/trust.bin")" = "new trust"
test "$(cat "$state/signed-trust-bundle.bin")" = "candidate signed bundle"
test "$(cat "$state/trust-signer-set.bin")" = "candidate signer set"

printf 'admitted usage\n' > "$state/usage.bin"
if run_reset "forbidden trust" "forbidden trust"; then
  echo "non-empty usage unexpectedly allowed a reset" >&2
  exit 1
fi
test "$(cat "$state/trust.bin")" = "new trust"
test "$(grep -c '^bootstrap ' "$test_root/launchctl.log")" -ge 3
echo "Kanalen testnet trust rebootstrap rehearsal passed"
