#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_id="${1:?usage: package-kanalen-release.sh <release-id> <output-dir> [cargo-target-dir]}"
output_dir="${2:?usage: package-kanalen-release.sh <release-id> <output-dir> [cargo-target-dir]}"
target_dir="${3:-$repo_root/target/release}"

release_dir="$output_dir/$release_id"
mkdir -p "$release_dir/bin" "$release_dir/scripts"
for binary in validator-node activechain-rpc-node activechain-rpc-ingest activechain-rpc-bootstrap activechain-rpc-probe; do
  test -x "$target_dir/$binary"
  install -m 755 "$target_dir/$binary" "$release_dir/bin/$binary"
done
install -m 755 "$repo_root/deploy/kanalen/scripts/run-kanalen-round.sh" "$release_dir/scripts/run-kanalen-round.sh"
printf '%s\n' "$release_id" > "$release_dir/REVISION"
printf 'packaged Kanalen release %s at %s\n' "$release_id" "$release_dir"
