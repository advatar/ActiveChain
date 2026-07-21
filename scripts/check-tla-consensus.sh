#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tool_cache=${ACTIVECHAIN_TLA_CACHE:-${TMPDIR:-/tmp}/activechain-tla-tools}
tla_version=1.8.0
tla_sha256=cc4803dce2a8ffaf0f5920a9dc39df4b5ee34ab4cb53fb58ac557277a7e516b3
tla_url="https://github.com/tlaplus/tlaplus/releases/download/v${tla_version}/tla2tools.jar"
tla_jar="$tool_cache/tla2tools-${tla_version}.jar"
java_image='eclipse-temurin@sha256:db1689535962d757a5adabf57387584ed543d38c0b9d1fe870123ea362ad73b0'
workers=${ACTIVECHAIN_TLC_WORKERS:-auto}

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
  curl --fail --location --retry 3 --output "$download" "$tla_url"
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
    -config ActiveChainConsensus.cfg \
    ActiveChainConsensus.tla
