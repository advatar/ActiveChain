#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/activechain-work-delivery-provision.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT

ACTIVECHAIN_KANALEN_ROOT="$test_root" \
  bash "$repo_root/deploy/kanalen/scripts/provision-work-delivery.sh"

token="$test_root/work-delivery/bearer.token"
test -s "$token"
test -d "$test_root/work-delivery/receipts"
first_token="$(cat "$token")"

ACTIVECHAIN_KANALEN_ROOT="$test_root" \
  bash "$repo_root/deploy/kanalen/scripts/provision-work-delivery.sh"
test "$(cat "$token")" = "$first_token"

chmod 0644 "$token"
if ACTIVECHAIN_KANALEN_ROOT="$test_root" \
  bash "$repo_root/deploy/kanalen/scripts/provision-work-delivery.sh"; then
  echo "insecure work-delivery token was accepted" >&2
  exit 1
fi

echo "work-delivery provisioning rehearsal passed"
