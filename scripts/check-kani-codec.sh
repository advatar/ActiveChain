#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
kani_version=0.67.0
process_timeout=${ACTIVECHAIN_KANI_PROCESS_TIMEOUT:-600}
harness_timeout=${ACTIVECHAIN_KANI_HARNESS_TIMEOUT:-120s}
jobs=${ACTIVECHAIN_KANI_JOBS:-2}
target_dir=${ACTIVECHAIN_KANI_TARGET_DIR:-${TMPDIR:-/tmp}/activechain-kani-codec}

command -v cargo-kani >/dev/null 2>&1 || {
  echo "cargo-kani ${kani_version} is required" >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required to enforce the Kani process timeout" >&2
  exit 1
}

actual_version=$(cargo kani --version)
if [[ "$actual_version" != "cargo-kani ${kani_version}" ]]; then
  echo "canonical codec proof gate requires cargo-kani ${kani_version}" >&2
  printf 'found: %s\n' "$actual_version" >&2
  exit 1
fi

mkdir -p "$target_dir"
kani_command=(
  cargo kani
  --manifest-path "$root/Cargo.toml"
  --package activechain-canonical-codec
  --lib
  --target-dir "$target_dir"
  --jobs "$jobs"
  --output-format terse
  --default-unwind 16
  -Z unstable-options
  --harness-timeout "$harness_timeout"
)

python3 - "$process_timeout" "${kani_command[@]}" <<'PY'
import os
import signal
import subprocess
import sys

timeout = int(sys.argv[1])
command = sys.argv[2:]
process = subprocess.Popen(command, start_new_session=True)
try:
    return_code = process.wait(timeout=timeout)
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    print(
        f"Kani codec proof gate exceeded {timeout} seconds",
        file=sys.stderr,
    )
    raise SystemExit(124)
raise SystemExit(return_code)
PY
