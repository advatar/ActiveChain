#!/usr/bin/env bash
set -euo pipefail

archive="${1:?usage: activate-kanalen-release.sh <archive> <checksum> <release-id>}"
checksum="${2:?usage: activate-kanalen-release.sh <archive> <checksum> <release-id>}"
release_id="${3:?usage: activate-kanalen-release.sh <archive> <checksum> <release-id>}"
deployment_root="${ACTIVECHAIN_KANALEN_ROOT:-$HOME/activechain-deploy/kanalen}"
launchctl_bin="${ACTIVECHAIN_LAUNCHCTL:-launchctl}"
plutil_bin="${ACTIVECHAIN_PLUTIL:-plutil}"
release_root="$deployment_root/releases"
release_dir="$release_root/$release_id"
staging_dir=""

cleanup() {
  if [[ -n "$staging_dir" && -d "$staging_dir" ]]; then
    rm -rf "$staging_dir"
  fi
}
trap cleanup EXIT

if [[ ! "$release_id" =~ ^[0-9a-f]{40}$ ]]; then
  echo "release ID must be a full lowercase Git commit: $release_id" >&2
  exit 1
fi
if [[ -L "$archive" || ! -f "$archive" || -L "$checksum" || ! -f "$checksum" ]]; then
  echo "release archive and checksum must be regular, non-symlink files" >&2
  exit 1
fi

expected_digest="$(awk 'NR == 1 { print $1 }' "$checksum")"
actual_digest="$(shasum -a 256 "$archive" | awk '{ print $1 }')"
if [[ ! "$expected_digest" =~ ^[0-9a-f]{64}$ || "$actual_digest" != "$expected_digest" ]]; then
  echo "release archive checksum mismatch" >&2
  exit 1
fi

while IFS= read -r entry; do
  case "$entry" in
    kanalen|kanalen/*) ;;
    *)
      echo "release archive contains an unexpected path: $entry" >&2
      exit 1
      ;;
  esac
  case "/$entry/" in
    */../*|*/./*)
      echo "release archive contains an unsafe path: $entry" >&2
      exit 1
      ;;
  esac
done < <(tar -tzf "$archive")

mkdir -p "$release_root"
if [[ -e "$release_dir" ]]; then
  if [[ ! -f "$release_dir/.archive.sha256" ]] ||
    [[ "$(cat "$release_dir/.archive.sha256")" != "$actual_digest" ]]; then
    echo "release directory already exists with different content: $release_dir" >&2
    exit 1
  fi
else
  staging_dir="$(mktemp -d "$release_root/.${release_id}.XXXXXX")"
  tar -xzf "$archive" -C "$staging_dir"
  if [[ ! -d "$staging_dir/kanalen" ]]; then
    echo "release archive does not contain the kanalen root" >&2
    exit 1
  fi
  printf '%s\n' "$actual_digest" >"$staging_dir/kanalen/.archive.sha256"
  mv "$staging_dir/kanalen" "$release_dir"
  rmdir "$staging_dir"
  staging_dir=""
fi

for binary in validator-node activechain-rpc-node activechain-telemetry-anchor-gateway actum-work-proof-api actum-work-proof-verifier actum-work-proof-trust-bootstrap; do
  if [[ ! -x "$release_dir/bin/$binary" ]]; then
    echo "release is missing executable $binary" >&2
    exit 1
  fi
done
if [[ ! -x "$release_dir/scripts/provision-work-proof-verifier.sh" ]]; then
  echo "release is missing the work-proof provisioning script" >&2
  exit 1
fi

candidate_network="$release_dir/network.env"
runtime_network="$deployment_root/network.env"
candidate_chain="$(sed -n 's/^ACTIVECHAIN_CHAIN_ID_HEX=//p' "$candidate_network")"
if [[ -z "$candidate_chain" ]]; then
  echo "candidate release has no chain ID" >&2
  exit 1
fi
if [[ -f "$runtime_network" ]]; then
  runtime_chain="$(sed -n 's/^ACTIVECHAIN_CHAIN_ID_HEX=//p' "$runtime_network")"
  if [[ -z "$runtime_chain" || "$runtime_chain" != "$candidate_chain" ]]; then
    echo "candidate release would substitute the deployed chain ID" >&2
    exit 1
  fi
else
  install -m 0644 "$candidate_network" "$runtime_network"
fi

ACTIVECHAIN_KANALEN_ROOT="$deployment_root" \
ACTIVECHAIN_WORK_PROOF_BINARY_DIR="$release_dir/bin" \
  bash "$release_dir/scripts/provision-work-proof-verifier.sh"

if [[ -e "$deployment_root/current" && ! -L "$deployment_root/current" ]]; then
  echo "current release path must be absent or a symlink" >&2
  exit 1
fi
ln -sfn "$release_dir" "$deployment_root/current"
mkdir -p "$HOME/Library/Logs/ActiveChain"

launch_domain="gui/$(id -u)"
for label in \
  dev.activechain.kanalen.validator0 \
  dev.activechain.kanalen.validator1 \
  dev.activechain.kanalen.validator2 \
  dev.activechain.kanalen.rpc \
  dev.activechain.kanalen.anchor \
  dev.activechain.kanalen.work-proof \
  dev.activechain.kanalen.round; do
  plist="$release_dir/launchagents/$label.plist"
  if [[ ! -f "$plist" ]]; then
    echo "release is missing launch agent $label" >&2
    exit 1
  fi
  "$plutil_bin" -lint "$plist" >/dev/null
  "$launchctl_bin" bootout "$launch_domain/$label" 2>/dev/null || true
  "$launchctl_bin" bootstrap "$launch_domain" "$plist"
done

echo "activated Kanalen release $release_id"
