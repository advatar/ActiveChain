#!/usr/bin/env bash
set -euo pipefail

deployment_root="${ACTIVECHAIN_KANALEN_ROOT:-$HOME/activechain-deploy/kanalen}"
state_dir="$deployment_root/work-proof"
binary_dir="${ACTIVECHAIN_WORK_PROOF_BINARY_DIR:-$deployment_root/current/bin}"
token_file="$state_dir/bearer.token"
trust_store="$state_dir/trust.bin"
signed_bundle="${ACTUM_WORK_PROOF_SIGNED_BUNDLE:-$state_dir/signed-trust-bundle.bin}"
signer_set="${ACTUM_WORK_PROOF_SIGNER_SET:-$state_dir/trust-signer-set.bin}"
bootstrap="$binary_dir/actum-work-proof-trust-bootstrap"
temporary_token=""

cleanup() {
  if [[ -n "$temporary_token" ]]; then
    rm -f "$temporary_token"
  fi
}
trap cleanup EXIT

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

umask 077
install -d -m 0700 "$state_dir"

if [[ ! -e "$token_file" ]]; then
  temporary_token="$(mktemp "$state_dir/.bearer.token.XXXXXX")"
  openssl rand -base64 48 >"$temporary_token"
  chmod 0600 "$temporary_token"
  mv "$temporary_token" "$token_file"
  temporary_token=""
fi
require_private_file "$token_file" "work-proof bearer token"

if [[ ! -e "$trust_store" ]]; then
  require_private_file "$signed_bundle" "signed trust bundle"
  require_private_file "$signer_set" "trust signer set"
  if [[ ! -x "$bootstrap" ]]; then
    echo "trust bootstrap binary is missing or not executable: $bootstrap" >&2
    exit 1
  fi
  now_ms="$(($(date +%s) * 1000))"
  "$bootstrap" "$trust_store" "$signed_bundle" "$signer_set" "$now_ms"
  chmod 0600 "$trust_store"
fi
require_private_file "$trust_store" "work-proof trust store"

echo "work-proof verifier state provisioned at $state_dir"
