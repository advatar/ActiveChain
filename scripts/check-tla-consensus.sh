#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tool_cache=${ACTIVECHAIN_TLA_CACHE:-${TMPDIR:-/tmp}/activechain-tla-tools}
tla_version=1.8.0
tla_asset_id=538706268
tla_sha256=dbcc75552f21978a4846688b8e23be1a6b6c0b3fcee35d78fec2df167958ec94
tla_url="https://api.github.com/repos/tlaplus/tlaplus/releases/assets/${tla_asset_id}"
tla_jar="$tool_cache/tla2tools-${tla_version}.jar"
java_image='eclipse-temurin@sha256:db1689535962d757a5adabf57387584ed543d38c0b9d1fe870123ea362ad73b0'
workers=${ACTIVECHAIN_TLC_WORKERS:-auto}
module=${1:-ActiveChainConsensus}
config=${2:-${module}.cfg}

if [[ "$module" == */* || "$config" == */* || "$module" == *..* || "$config" == *..* ]]; then
  echo "TLA+ module and configuration must be filenames under formal/tla" >&2
  exit 1
fi
if [[ ! -f "$root/formal/tla/${module}.tla" || ! -f "$root/formal/tla/$config" ]]; then
  echo "missing TLA+ module or configuration: $module / $config" >&2
  exit 1
fi

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "a SHA-256 implementation (sha256sum or shasum) is required" >&2
    return 1
  fi
}

mkdir -p "$tool_cache"
if [[ ! -f "$tla_jar" ]] || [[ "$(sha256_file "$tla_jar")" != "$tla_sha256" ]]; then
  command -v curl >/dev/null 2>&1 || {
    echo "curl is required to fetch the pinned TLA+ tools jar" >&2
    exit 1
  }
  download="$tla_jar.download.$$"
  trap 'rm -f "$download"' EXIT
  curl --fail --location --retry 3 \
    --header 'Accept: application/octet-stream' \
    --output "$download" "$tla_url"
  actual_sha256=$(sha256_file "$download")
  if [[ "$actual_sha256" != "$tla_sha256" ]]; then
    echo "TLA+ tools SHA-256 mismatch: expected $tla_sha256, got $actual_sha256" >&2
    exit 1
  fi
  mv "$download" "$tla_jar"
  trap - EXIT
fi

if ! docker version >/dev/null 2>&1; then
  echo "Docker is required because the host Java runtime is not part of the proof toolchain" >&2
  exit 1
fi

if ! docker image inspect "$java_image" >/dev/null 2>&1; then
  docker pull "$java_image"
fi

docker run --rm \
  --volume "$root:/work:ro" \
  --volume "$tla_jar:/opt/tla2tools.jar:ro" \
  --workdir /work/formal/tla \
  "$java_image" \
  java -XX:+UseParallelGC -cp /opt/tla2tools.jar tlc2.TLC \
    -metadir /tmp/activechain-tlc-states \
    -seed 20260721 \
    -fp 0 \
    -workers "$workers" \
    -config "$config" \
    "${module}.tla"
