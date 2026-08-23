#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_id="${1:?usage: package-kanalen-release.sh <release-id> <output-dir> [cargo-target-dir]}"
output_dir="${2:?usage: package-kanalen-release.sh <release-id> <output-dir> [cargo-target-dir]}"
target_dir="${3:-$repo_root/target/release}"

release_dir="$output_dir/$release_id"
mkdir -p "$release_dir/bin" "$release_dir/scripts" "$release_dir/launchagents"
for binary in validator-node genesis-tool cash-genesis-tool activechain-rpc-node activechain-rpc-ingest activechain-rpc-bootstrap activechain-rpc-probe activechain-transfer-spool activechain-telemetry-anchor-gateway actum-work-proof-verifier actum-work-proof-json-verifier actum-work-proof-api actum-work-proof-trust-bootstrap actum-work-delivery-api; do
  test -x "$target_dir/$binary"
  install -m 755 "$target_dir/$binary" "$release_dir/bin/$binary"
done

mkdir -p "$release_dir/docs"
install -m 0644 docs/pow-actum-network-deployment.md "$release_dir/docs/"
install -m 0644 deploy/kanalen/network.env deploy/kanalen/ports.env "$release_dir/"
cp -R deploy/kanalen/gateway "$release_dir/"
install -m 755 "$repo_root/deploy/kanalen/scripts/run-kanalen-round.sh" "$release_dir/scripts/run-kanalen-round.sh"
install -m 755 "$repo_root/deploy/kanalen/scripts/reset-kanalen-state.sh" "$release_dir/scripts/reset-kanalen-state.sh"
install -m 755 "$repo_root/deploy/kanalen/scripts/provision-work-proof-verifier.sh" "$release_dir/scripts/provision-work-proof-verifier.sh"
install -m 755 "$repo_root/deploy/kanalen/scripts/provision-work-delivery.sh" "$release_dir/scripts/provision-work-delivery.sh"
install -m 755 "$repo_root/scripts/check-validator-snapshot.sh" "$release_dir/scripts/check-validator-snapshot.sh"
install -m 755 "$repo_root/scripts/check-execution-snapshot.sh" "$release_dir/scripts/check-execution-snapshot.sh"
for launchagent in "$repo_root"/deploy/kanalen/launchagents/*.plist; do
  install -m 644 "$launchagent" "$release_dir/launchagents/$(basename "$launchagent")"
done
printf '%s\n' "$release_id" > "$release_dir/REVISION"
printf 'packaged Kanalen release %s at %s\n' "$release_id" "$release_dir"
