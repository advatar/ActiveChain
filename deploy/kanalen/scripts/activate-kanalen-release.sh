#!/usr/bin/env bash
set -euo pipefail

archive="${1:?usage: activate-kanalen-release.sh <archive> <checksum> <release-id>}"
checksum="${2:?usage: activate-kanalen-release.sh <archive> <checksum> <release-id>}"
release_id="${3:?usage: activate-kanalen-release.sh <archive> <checksum> <release-id>}"
# The network this release belongs to. Everything below derives from it, so a
# second network needs a different value rather than a second copy of this
# script -- which is how the literal name ended up in twenty places.
network="${ACTIVECHAIN_NETWORK:-kanalen}"
deployment_root="${ACTIVECHAIN_NETWORK_ROOT:-${ACTIVECHAIN_KANALEN_ROOT:-$HOME/activechain-deploy/$network}}"
launchctl_bin="${ACTIVECHAIN_LAUNCHCTL:-launchctl}"
plutil_bin="${ACTIVECHAIN_PLUTIL:-plutil}"
plistbuddy_bin="${ACTIVECHAIN_PLISTBUDDY:-/usr/libexec/PlistBuddy}"
# Resolved rather than inherited: this script is normally run over ssh as
# `bash activate-kanalen-release.sh`, which gets a non-login shell whose PATH
# does not include Homebrew or Docker Desktop. Depending on the caller's PATH
# meant a deployment that had already restarted every service then aborted at
# the gateway step with "docker: command not found".
docker_bin="${ACTIVECHAIN_DOCKER:-}"
if [[ -z "$docker_bin" ]]; then
  for candidate in \
    docker \
    /opt/homebrew/bin/docker \
    /usr/local/bin/docker \
    /Applications/Docker.app/Contents/Resources/bin/docker; do
    if command -v "$candidate" >/dev/null 2>&1; then
      docker_bin="$candidate"
      break
    fi
  done
fi
if [[ -z "$docker_bin" ]]; then
  echo "could not find docker; set ACTIVECHAIN_DOCKER to its path" >&2
  exit 1
fi
# Docker Desktop records `credsStore: desktop` in the user's config. Its CLI
# may be available through /usr/local/bin while the matching credential helper
# exists only in the application bundle, especially in a non-login SSH shell.
docker_desktop_bin="/Applications/Docker.app/Contents/Resources/bin"
if [[ -d "$docker_desktop_bin" ]]; then
  export PATH="$docker_desktop_bin:$PATH"
fi
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
    "$network"|"$network"/*) ;;
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
  if [[ ! -d "$staging_dir/$network" ]]; then
    echo "release archive does not contain the $network root" >&2
    exit 1
  fi
  printf '%s\n' "$actual_digest" >"$staging_dir/$network/.archive.sha256"
  mv "$staging_dir/$network" "$release_dir"
  rmdir "$staging_dir"
  staging_dir=""
fi

for binary in validator-node activechain-rpc-node activechain-transfer-spool activechain-telemetry-anchor-gateway actum-work-proof-api actum-work-proof-verifier actum-work-proof-trust-bootstrap actum-work-prover actum-work-delivery-api; do
  if [[ ! -x "$release_dir/bin/$binary" ]]; then
    echo "release is missing executable $binary" >&2
    exit 1
  fi
done
if [[ ! -x "$release_dir/scripts/provision-work-proof-verifier.sh" ]]; then
  echo "release is missing the work-proof provisioning script" >&2
  exit 1
fi
if [[ ! -x "$release_dir/scripts/provision-work-delivery.sh" ]]; then
  echo "release is missing the work-delivery provisioning script" >&2
  exit 1
fi
for gateway_file in compose.yml dynamic.yml traefik.yml switch-edge.sh; do
  if [[ ! -f "$release_dir/gateway/$gateway_file" ]]; then
    echo "release is missing gateway/$gateway_file" >&2
    exit 1
  fi
done

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

# The cash treasury owner is regenerated by every state reset and recorded in
# network.env, but launchd cannot read that file. Without it the RPC infers the
# faucet source from "the only cash owner", which stops being true the moment
# the faucet pays anyone, and the node then refuses to start.
cash_owner=$(sed -n 's/^ACTIVECHAIN_CASH_GENESIS_OWNER_HEX=//p' "$runtime_network")
if [[ -n "$cash_owner" ]]; then
  rpc_plist="$release_dir/launchagents/dev.activechain.$network.rpc.plist"
  "$plistbuddy_bin" \
    -c "Add :EnvironmentVariables:ACTIVECHAIN_CASH_GENESIS_OWNER_HEX string $cash_owner" \
    "$rpc_plist" 2>/dev/null ||
    "$plistbuddy_bin" \
      -c "Set :EnvironmentVariables:ACTIVECHAIN_CASH_GENESIS_OWNER_HEX $cash_owner" \
      "$rpc_plist"
  "$plutil_bin" -lint "$rpc_plist" >/dev/null
fi

runtime_genesis=$(sed -n 's/^ACTIVECHAIN_GENESIS_COMMITMENT_HEX=//p' "$runtime_network")
if [[ ! "$candidate_chain" =~ ^[0-9a-f]{96}$ ||
  ! "$runtime_genesis" =~ ^[0-9a-f]{96}$ ]]; then
  echo "runtime network identity is missing or malformed" >&2
  exit 1
fi
delivery_plist="$release_dir/launchagents/dev.activechain.$network.work-delivery.plist"
if [[ ! -f "$delivery_plist" ]]; then
  echo "release is missing the work-delivery launch agent" >&2
  exit 1
fi
"$plistbuddy_bin" -c "Set :ProgramArguments:4 $candidate_chain" "$delivery_plist"
"$plistbuddy_bin" -c "Set :ProgramArguments:5 $runtime_genesis" "$delivery_plist"
"$plistbuddy_bin" -c "Set :ProgramArguments:6 $release_id" "$delivery_plist"
"$plutil_bin" -lint "$delivery_plist" >/dev/null

ACTIVECHAIN_KANALEN_ROOT="$deployment_root" \
ACTIVECHAIN_WORK_PROOF_BINARY_DIR="$release_dir/bin" \
  bash "$release_dir/scripts/provision-work-proof-verifier.sh"
ACTIVECHAIN_KANALEN_ROOT="$deployment_root" \
  bash "$release_dir/scripts/provision-work-delivery.sh"

if [[ -e "$deployment_root/current" && ! -L "$deployment_root/current" ]]; then
  echo "current release path must be absent or a symlink" >&2
  exit 1
fi
ln -sfn "$release_dir" "$deployment_root/current"
mkdir -p "$HOME/Library/Logs/ActiveChain"

launch_domain="gui/$(id -u)"
shopt -s nullglob
agents=("$release_dir"/launchagents/dev.activechain."$network".*.plist)
shopt -u nullglob
if [[ ${#agents[@]} -eq 0 ]]; then
  echo "release contains no launch agents for $network" >&2
  exit 1
fi
for plist in "${agents[@]}"; do
  label="$(basename "$plist" .plist)"
  "$plutil_bin" -lint "$plist" >/dev/null
  "$launchctl_bin" bootout "$launch_domain/$label" 2>/dev/null || true
  # launchd unloads asynchronously. Bootstrapping straight after a bootout
  # races the old job's departure and fails with EIO ("Bootstrap failed: 5:
  # Input/output error") -- which, because the bootout already succeeded,
  # leaves the service *down* and aborts the rest of the activation. That is
  # how a deployment took a validator offline. Wait for the label to leave the
  # domain, then retry a bounded number of times.
  for _ in $(seq 1 50); do
    "$launchctl_bin" print "$launch_domain/$label" >/dev/null 2>&1 || break
    sleep 0.2
  done
  bootstrapped=0
  for attempt in 1 2 3 4 5; do
    if "$launchctl_bin" bootstrap "$launch_domain" "$plist" 2>/dev/null; then
      bootstrapped=1
      break
    fi
    echo "bootstrap of $label did not take on attempt $attempt; retrying" >&2
    sleep 1
  done
  if [[ "$bootstrapped" -ne 1 ]]; then
    echo "could not bootstrap $label into $launch_domain" >&2
    exit 1
  fi
done

gateway_dir="$deployment_root/gateway"
install -d -m 0755 "$gateway_dir"
install -d -m 0700 "$gateway_dir/letsencrypt"
for gateway_file in compose.yml dynamic.yml traefik.yml; do
  install -m 0644 "$release_dir/gateway/$gateway_file" "$gateway_dir/$gateway_file"
done
install -m 0755 "$release_dir/gateway/switch-edge.sh" "$gateway_dir/switch-edge.sh"
if [[ -f "$release_dir/gateway/README.md" ]]; then
  install -m 0644 "$release_dir/gateway/README.md" "$gateway_dir/README.md"
fi
if [[ -f "$release_dir/gateway/$network.Caddyfile" ]]; then
  install -m 0644 "$release_dir/gateway/$network.Caddyfile" "$gateway_dir/$network.Caddyfile"
fi
"$docker_bin" compose -f "$gateway_dir/compose.yml" config >/dev/null
"$docker_bin" compose -f "$gateway_dir/compose.yml" up -d

echo "activated Kanalen release $release_id"
