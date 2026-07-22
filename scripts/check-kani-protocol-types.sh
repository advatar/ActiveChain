#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
kani_version=0.67.0
process_timeout=${ACTIVECHAIN_KANI_PROCESS_TIMEOUT:-600}
harness_timeout=${ACTIVECHAIN_KANI_HARNESS_TIMEOUT:-180s}
jobs=${ACTIVECHAIN_KANI_JOBS:-2}
target_dir=${ACTIVECHAIN_KANI_TARGET_DIR:-${TMPDIR:-/tmp}/activechain-kani-protocol-types}

command -v cargo-kani >/dev/null 2>&1 || { echo "cargo-kani ${kani_version} is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
actual_version=$(cargo kani --version)
if [[ "$actual_version" != "cargo-kani ${kani_version}" ]]; then
  echo "protocol-types proof gate requires cargo-kani ${kani_version}; found: $actual_version" >&2
  exit 1
fi

mkdir -p "$target_dir"
kani_command=(cargo kani --manifest-path "$root/Cargo.toml" --package activechain-protocol-types
  --lib --target-dir "$target_dir" --jobs "$jobs" --output-format terse --default-unwind 64
  -Z unstable-options --harness-timeout "$harness_timeout")

python3 - "$process_timeout" "${kani_command[@]}" <<'PY'
import os, signal, subprocess, sys
timeout = int(sys.argv[1])
process = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    code = process.wait(timeout=timeout)
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    print(f"Kani protocol-types proof gate exceeded {timeout} seconds", file=sys.stderr)
    raise SystemExit(124)
raise SystemExit(code)
PY
