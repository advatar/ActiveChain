#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/activechain-work-proof-provision.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT

mkdir -p "$test_root/current/bin" "$test_root/work-proof"
printf 'signed bundle fixture\n' >"$test_root/work-proof/signed-trust-bundle.bin"
printf 'signer set fixture\n' >"$test_root/work-proof/trust-signer-set.bin"
chmod 0600 "$test_root/work-proof/signed-trust-bundle.bin" "$test_root/work-proof/trust-signer-set.bin"

cat >"$test_root/current/bin/actum-work-proof-trust-bootstrap" <<'BOOTSTRAP'
#!/usr/bin/env bash
set -euo pipefail
output="$1"
bundle="$2"
signers="$3"
now_ms="$4"
test -s "$bundle"
test -s "$signers"
test "$now_ms" -gt 0
printf 'qualified trust store\n' >"$output"
printf '%s\n' "$output" >>"${output}.calls"
BOOTSTRAP
chmod 0755 "$test_root/current/bin/actum-work-proof-trust-bootstrap"

ACTIVECHAIN_KANALEN_ROOT="$test_root" \
  bash "$repo_root/deploy/kanalen/scripts/provision-work-proof-verifier.sh"

test -s "$test_root/work-proof/bearer.token"
test -s "$test_root/work-proof/trust.bin"
test "$(wc -l <"$test_root/work-proof/trust.bin.calls" | tr -d ' ')" = 1
first_token="$(cat "$test_root/work-proof/bearer.token")"

cat >"$test_root/current/bin/actum-work-proof-trust-bootstrap" <<'BOOTSTRAP'
#!/usr/bin/env bash
exit 99
BOOTSTRAP
chmod 0755 "$test_root/current/bin/actum-work-proof-trust-bootstrap"

ACTIVECHAIN_KANALEN_ROOT="$test_root" \
  bash "$repo_root/deploy/kanalen/scripts/provision-work-proof-verifier.sh"

test "$(cat "$test_root/work-proof/bearer.token")" = "$first_token"
test "$(wc -l <"$test_root/work-proof/trust.bin.calls" | tr -d ' ')" = 1

echo "work-proof verifier provisioning rehearsal passed"
