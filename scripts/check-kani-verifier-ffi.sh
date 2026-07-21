#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
manifest="$root/crates/verifier-ffi/kani-workspace/Cargo.toml"
kani_version=0.67.0
process_timeout=${ACTIVECHAIN_KANI_FFI_PROCESS_TIMEOUT:-600}
harness_timeout=${ACTIVECHAIN_KANI_FFI_HARNESS_TIMEOUT:-180s}
jobs=${ACTIVECHAIN_KANI_FFI_JOBS:-2}
target_dir=${ACTIVECHAIN_KANI_FFI_TARGET_DIR:-${TMPDIR:-/tmp}/activechain-kani-verifier-ffi}

command -v cargo-kani >/dev/null 2>&1 || {
  echo "cargo-kani ${kani_version} is required" >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required for verifier-FFI proof preflight and timeout enforcement" >&2
  exit 1
}

actual_version=$(cargo kani --version)
if [[ "$actual_version" != "cargo-kani ${kani_version}" ]]; then
  echo "verifier-FFI proof gate requires cargo-kani ${kani_version}" >&2
  printf 'found: %s\n' "$actual_version" >&2
  exit 1
fi

# The pinned Kani bundle carries Rust 1.93, while the main workspace declares a newer MSRV. The
# verification workspace changes metadata only: this preflight proves that every local target still
# resolves to the production source and that its external dependency lock agrees with the root lock.
python3 - "$root" "$manifest" <<'PY'
import json
from pathlib import Path
import subprocess
import sys
import tomllib

root = Path(sys.argv[1]).resolve()
manifest = Path(sys.argv[2]).resolve()
metadata = json.loads(
    subprocess.check_output(
        [
            "cargo",
            "metadata",
            "--manifest-path",
            str(manifest),
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ],
        text=True,
    )
)

expected_sources = {
    "activechain-canonical-codec": root / "crates/canonical-codec/src/lib.rs",
    "activechain-protocol-types": root / "crates/protocol-types/src/lib.rs",
    "activechain-verifier-api": root / "crates/verifier-api/src/lib.rs",
    "activechain-verifier-ffi": root / "crates/verifier-ffi/src/lib.rs",
}
packages = {package["name"]: package for package in metadata["packages"]}
if set(packages) != set(expected_sources):
    raise SystemExit(
        "verifier-FFI Kani workspace package set diverged: "
        f"expected {sorted(expected_sources)}, found {sorted(packages)}"
    )
for name, expected in expected_sources.items():
    package = packages[name]
    sources = {Path(target["src_path"]).resolve() for target in package["targets"]}
    if expected.resolve() not in sources:
        raise SystemExit(
            f"{name} proof targets are {sorted(map(str, sources))}, "
            f"expected production source {expected}"
        )
    if package["rust_version"] != "1.93.0":
        raise SystemExit(f"{name} proof metadata must remain pinned to Rust 1.93.0")

def external_lock_entries(path: Path):
    lock = tomllib.loads(path.read_text())
    return {
        (entry["name"], entry["version"], entry.get("source"), entry.get("checksum"))
        for entry in lock["package"]
        if entry.get("source") is not None
    }

root_external = external_lock_entries(root / "Cargo.lock")
proof_external = external_lock_entries(manifest.parent / "Cargo.lock")
missing = sorted(proof_external - root_external)
if missing:
    raise SystemExit(
        "verifier-FFI Kani dependency lock diverged from the production workspace: "
        + repr(missing)
    )
PY

mkdir -p "$target_dir"
kani_command=(
  cargo kani
  --manifest-path "$manifest"
  --package activechain-verifier-ffi
  --lib
  --target-dir "$target_dir"
  --jobs "$jobs"
  --output-format terse
  --default-unwind 80
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
environment = os.environ.copy()
environment["CARGO_NET_OFFLINE"] = "true"
process = subprocess.Popen(command, env=environment, start_new_session=True)
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
        f"Kani verifier-FFI proof gate exceeded {timeout} seconds",
        file=sys.stderr,
    )
    raise SystemExit(124)
raise SystemExit(return_code)
PY
