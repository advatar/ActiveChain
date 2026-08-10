#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/activechain-kanalen-activation.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT
release_id="0123456789abcdef0123456789abcdef01234567"
payload="$test_root/payload/kanalen"
deployment="$test_root/deployment"
archive="$test_root/kanalen-$release_id.tar.gz"
checksum="$test_root/kanalen-$release_id.sha256"

mkdir -p "$payload/bin" "$payload/scripts" "$payload/launchagents" "$payload/gateway" "$deployment/work-proof" "$test_root/tools"
for binary in validator-node activechain-rpc-node activechain-telemetry-anchor-gateway actum-work-proof-api actum-work-proof-verifier; do
  printf '#!/bin/sh\nexit 0\n' >"$payload/bin/$binary"
  chmod 0755 "$payload/bin/$binary"
done

for gateway_file in compose.yml dynamic.yml traefik.yml; do
  printf 'fixture: true\n' >"$payload/gateway/$gateway_file"
done
printf '#!/bin/sh\nexit 0\n' >"$payload/gateway/switch-edge.sh"
chmod 0755 "$payload/gateway/switch-edge.sh"
cat >"$payload/bin/actum-work-proof-trust-bootstrap" <<'BOOTSTRAP'
#!/bin/bash
set -euo pipefail
printf 'activated trust\n' >"$1"
BOOTSTRAP
chmod 0755 "$payload/bin/actum-work-proof-trust-bootstrap"
cp "$repo_root/deploy/kanalen/scripts/provision-work-proof-verifier.sh" "$payload/scripts/"
chmod 0755 "$payload/scripts/provision-work-proof-verifier.sh"
printf 'ACTIVECHAIN_CHAIN_ID_HEX=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' >"$payload/network.env"

for label in \
  dev.activechain.kanalen.validator0 \
  dev.activechain.kanalen.validator1 \
  dev.activechain.kanalen.validator2 \
  dev.activechain.kanalen.rpc \
  dev.activechain.kanalen.anchor \
  dev.activechain.kanalen.work-proof \
  dev.activechain.kanalen.round; do
  printf '<plist version="1.0"><dict/></plist>\n' >"$payload/launchagents/$label.plist"
done

printf 'signed trust fixture\n' >"$deployment/work-proof/signed-trust-bundle.bin"
printf 'signer set fixture\n' >"$deployment/work-proof/trust-signer-set.bin"
chmod 0600 "$deployment/work-proof/signed-trust-bundle.bin" "$deployment/work-proof/trust-signer-set.bin"

cat >"$test_root/tools/launchctl" <<'LAUNCHCTL'
#!/bin/bash
printf '%s\n' "$*" >>"$ACTIVECHAIN_LAUNCHCTL_LOG"
LAUNCHCTL
cat >"$test_root/tools/plutil" <<'PLUTIL'
#!/bin/bash
exit 0
PLUTIL
cat >"$test_root/tools/docker" <<'DOCKER'
#!/bin/bash
printf '%s\n' "$*" >>"$ACTIVECHAIN_DOCKER_LOG"
DOCKER
chmod 0755 "$test_root/tools/launchctl" "$test_root/tools/plutil" "$test_root/tools/docker"

tar -czf "$archive" -C "$test_root/payload" kanalen
shasum -a 256 "$archive" >"$checksum"

ACTIVECHAIN_KANALEN_ROOT="$deployment" \
ACTIVECHAIN_LAUNCHCTL="$test_root/tools/launchctl" \
ACTIVECHAIN_LAUNCHCTL_LOG="$test_root/launchctl.log" \
ACTIVECHAIN_PLUTIL="$test_root/tools/plutil" \
ACTIVECHAIN_DOCKER="$test_root/tools/docker" \
ACTIVECHAIN_DOCKER_LOG="$test_root/docker.log" \
  bash "$repo_root/deploy/kanalen/scripts/activate-kanalen-release.sh" \
    "$archive" "$checksum" "$release_id"

test -L "$deployment/current"
test "$(readlink "$deployment/current")" = "$deployment/releases/$release_id"
test -s "$deployment/work-proof/trust.bin"
test -s "$deployment/work-proof/bearer.token"
test "$(grep -c '^bootstrap ' "$test_root/launchctl.log")" = 7
test "$(grep -c '^compose ' "$test_root/docker.log")" = 2

ACTIVECHAIN_KANALEN_ROOT="$deployment" \
ACTIVECHAIN_LAUNCHCTL="$test_root/tools/launchctl" \
ACTIVECHAIN_LAUNCHCTL_LOG="$test_root/launchctl.log" \
ACTIVECHAIN_PLUTIL="$test_root/tools/plutil" \
ACTIVECHAIN_DOCKER="$test_root/tools/docker" \
ACTIVECHAIN_DOCKER_LOG="$test_root/docker.log" \
  bash "$repo_root/deploy/kanalen/scripts/activate-kanalen-release.sh" \
    "$archive" "$checksum" "$release_id"

test "$(grep -c '^bootstrap ' "$test_root/launchctl.log")" = 14
test "$(grep -c '^compose ' "$test_root/docker.log")" = 4
echo "Kanalen release activation rehearsal passed"
