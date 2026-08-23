#!/usr/bin/env bash
set -euo pipefail

deployment_root="${ACTIVECHAIN_NETWORK_ROOT:-${ACTIVECHAIN_KANALEN_ROOT:-$HOME/activechain-deploy/${ACTIVECHAIN_NETWORK:-kanalen}}}"
state_dir="$deployment_root/work-delivery"
token_file="$state_dir/bearer.token"
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

umask 077
install -d -m 0700 "$state_dir" "$state_dir/receipts"
if [[ ! -e "$token_file" ]]; then
  temporary_token="$(mktemp "$state_dir/.bearer.token.XXXXXX")"
  openssl rand -base64 48 >"$temporary_token"
  chmod 0600 "$temporary_token"
  mv "$temporary_token" "$token_file"
  temporary_token=""
fi
if [[ -L "$token_file" || ! -f "$token_file" ]]; then
  echo "work-delivery bearer token must be a regular, non-symlink file" >&2
  exit 1
fi
case "$(file_mode "$token_file")" in
  400|600) ;;
  *)
    echo "work-delivery bearer token must have mode 0400 or 0600" >&2
    exit 1
    ;;
esac

echo "work-delivery state provisioned at $state_dir"
