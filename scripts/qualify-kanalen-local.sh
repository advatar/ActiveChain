#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
skip_build=0
dry_run=0

usage() {
  echo "usage: scripts/qualify-kanalen-local.sh [--skip-build] [--dry-run]" >&2
}

while (($# > 0)); do
  case "$1" in
    --skip-build) skip_build=1 ;;
    --dry-run) dry_run=1 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

run() {
  printf ' +'
  printf ' %q' "$@"
  printf '\n'
  if ((dry_run == 0)); then
    "$@"
  fi
}

cd "$repo_root"

if ((skip_build == 0)); then
  run cargo build --locked --release \
    -p activechain-consensus-runtime \
    -p activechain-rpc-server \
    -p activechain-wallet-core \
    -p activechain-wallet-ffi \
    -p activechain-verifier-ffi
fi

run bash scripts/check-verifier-manifest.sh
run cargo test --locked -p activechain-verifier-api
run bash scripts/test-kanalen-round-cash-gate.sh
run bash scripts/rehearse-testnet-wallet-acceptance.sh

if ((dry_run == 0)); then
  release_root="$(mktemp -d "${TMPDIR:-/tmp}/activechain-kanalen-release.XXXXXX")"
  trap 'rm -rf "$release_root"' EXIT
  revision="$(git rev-parse --short=12 HEAD)"
  run bash scripts/package-kanalen-release.sh "local-$revision" "$release_root"
fi

echo "Kanalen local developmental testnet qualification passed"
