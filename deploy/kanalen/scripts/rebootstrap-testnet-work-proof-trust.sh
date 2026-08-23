#!/usr/bin/env bash
set -euo pipefail

signed_bundle="${1:?usage: rebootstrap-testnet-work-proof-trust.sh <signed-bundle> <signer-set> <expected-revision>}"
signer_set="${2:?usage: rebootstrap-testnet-work-proof-trust.sh <signed-bundle> <signer-set> <expected-revision>}"
expected_revision="${3:?usage: rebootstrap-testnet-work-proof-trust.sh <signed-bundle> <signer-set> <expected-revision>}"
deployment_root="${ACTIVECHAIN_NETWORK_ROOT:-${ACTIVECHAIN_KANALEN_ROOT:-$HOME/activechain-deploy/kanalen}}"
launchctl_bin="${ACTIVECHAIN_LAUNCHCTL:-launchctl}"
health_check="${ACTIVECHAIN_WORK_PROOF_HEALTH_CHECK:-}"
health_attempts="${ACTIVECHAIN_WORK_PROOF_HEALTH_ATTEMPTS:-30}"
chain_id="b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0b095e6cfe944bd2c9f6535b4c927782f1"
genesis="a836c4d201cda6ba33a01aa48011cf5f4d6acdfd1ec409d322dc1b56ed3552a25dcb158e0b1ec0352728653d315d477c"
state_dir="$deployment_root/work-proof"
usage_store="$state_dir/usage.bin"
trust_store="$state_dir/trust.bin"
token_file="$state_dir/bearer.token"
current="$deployment_root/current"
label="dev.activechain.kanalen.work-proof"
launch_domain="gui/$(id -u)"
candidate=""
service_stopped=false
replacement_installed=false
archive_dir=""

file_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

require_private_file() {
  local path="$1"
  local description="$2"
  if [[ -L "$path" || ! -f "$path" ]]; then
    echo "$description must be a regular, non-symlink file: $path" >&2
    exit 1
  fi
  case "$(file_mode "$path")" in
    400|600) ;;
    *)
      echo "$description must have mode 0400 or 0600: $path" >&2
      exit 1
      ;;
  esac
}

start_service() {
  "$launchctl_bin" bootstrap "$launch_domain" \
    "$current/launchagents/$label.plist"
  service_stopped=false
}

authenticated_health() {
  if [[ -n "$health_check" ]]; then
    "$health_check" "$token_file"
    return
  fi
  python3 - "$token_file" <<'PY'
import json
from pathlib import Path
import sys
import urllib.request

token = Path(sys.argv[1]).read_text().strip()
request = urllib.request.Request(
    "http://127.0.0.1:49157/v1/status",
    headers={"Authorization": f"Bearer {token}"},
)
with urllib.request.urlopen(request, timeout=5) as response:
    body = json.load(response)
if response.status != 200 or body.get("status") != "healthy":
    raise SystemExit("work-proof verifier did not report healthy")
PY
}

rollback() {
  local status=$?
  trap - EXIT
  if [[ "$replacement_installed" == true && -n "$archive_dir" ]]; then
    install -m 0600 "$archive_dir/trust.bin" "$trust_store"
    install -m 0600 "$archive_dir/signed-trust-bundle.bin" \
      "$state_dir/signed-trust-bundle.bin"
    install -m 0600 "$archive_dir/trust-signer-set.bin" \
      "$state_dir/trust-signer-set.bin"
  fi
  if [[ "$service_stopped" == true ]]; then
    start_service >/dev/null 2>&1 || true
  fi
  if [[ -n "$candidate" ]]; then
    rm -f "$candidate"
  fi
  exit "$status"
}
trap rollback EXIT

if [[ ! "$expected_revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "expected revision must be a full lowercase Git commit" >&2
  exit 1
fi
if [[ ! "$health_attempts" =~ ^[1-9][0-9]*$ ]]; then
  echo "health attempts must be a positive integer" >&2
  exit 1
fi
if [[ ! -L "$current" || "$(basename "$(readlink "$current")")" != "$expected_revision" ]]; then
  echo "active Kanalen revision does not match $expected_revision" >&2
  exit 1
fi
require_private_file "$signed_bundle" "candidate signed trust bundle"
require_private_file "$signer_set" "candidate trust signer set"
require_private_file "$trust_store" "current trust store"
require_private_file "$state_dir/signed-trust-bundle.bin" "current signed trust bundle"
require_private_file "$state_dir/trust-signer-set.bin" "current trust signer set"
require_private_file "$token_file" "work-proof bearer token"
bootstrap="$current/bin/actum-work-proof-testnet-trust-bootstrap"
if [[ ! -x "$bootstrap" ]]; then
  echo "testnet trust bootstrap binary is missing or not executable" >&2
  exit 1
fi

umask 077
"$launchctl_bin" bootout "$launch_domain/$label"
service_stopped=true
for _ in $(seq 1 50); do
  "$launchctl_bin" print "$launch_domain/$label" >/dev/null 2>&1 || break
  sleep 0.2
done

candidate="$(mktemp "$state_dir/.testnet-trust-candidate.XXXXXX")"
rm -f "$candidate"
now_ms="$(($(date +%s) * 1000))"
"$bootstrap" "$candidate" "$signed_bundle" "$signer_set" "$usage_store" \
  "$now_ms" "$chain_id" "$genesis"
chmod 0600 "$candidate"

bundle_digest="$(shasum -a 256 "$signed_bundle" | awk '{print $1}')"
install -d -m 0700 "$state_dir/trust-archive"
archive_dir="$(mktemp -d "$state_dir/trust-archive/$(date -u +%Y%m%dT%H%M%SZ)-$bundle_digest.XXXXXX")"
install -m 0600 "$trust_store" "$archive_dir/trust.bin"
install -m 0600 "$state_dir/signed-trust-bundle.bin" \
  "$archive_dir/signed-trust-bundle.bin"
install -m 0600 "$state_dir/trust-signer-set.bin" \
  "$archive_dir/trust-signer-set.bin"

install -m 0600 "$signed_bundle" "$state_dir/.signed-trust-bundle.bin.new"
install -m 0600 "$signer_set" "$state_dir/.trust-signer-set.bin.new"
mv "$state_dir/.signed-trust-bundle.bin.new" "$state_dir/signed-trust-bundle.bin"
mv "$state_dir/.trust-signer-set.bin.new" "$state_dir/trust-signer-set.bin"
mv "$candidate" "$trust_store"
candidate=""
replacement_installed=true

start_service
for _ in $(seq 1 "$health_attempts"); do
  if authenticated_health >/dev/null 2>&1; then
    trap - EXIT
    echo "Kanalen testnet trust rebootstrap installed; rollback archive: $archive_dir"
    exit 0
  fi
  sleep 1
done
echo "rebootstrapped verifier did not become healthy; restoring prior trust" >&2
service_stopped=true
"$launchctl_bin" bootout "$launch_domain/$label" >/dev/null 2>&1 || true
exit 1
