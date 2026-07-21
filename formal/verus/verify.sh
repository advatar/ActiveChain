#!/bin/sh
set -eu

VERUS_VERSION="0.2026.05.24.ecee80a"
VERUS_RELEASE_TAG="release/0.2026.05.24.ecee80a"
VERUS_RELEASE_COMMIT="ecee80a2139923d503338e6989f79fb690ec7847"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PLATFORM=$(uname -s)
ARCHITECTURE=$(uname -m)

case "$PLATFORM:$ARCHITECTURE" in
    Darwin:arm64)
        VERUS_ARCHIVE="verus-${VERUS_VERSION}-arm64-macos.zip"
        VERUS_ARCHIVE_SHA256="792f4b4d616aeee0cdef9804f8b0ecf03012a305c9cf7626c406b32b9a0713ac"
        VERUS_DIRECTORY="verus-arm64-macos"
        ;;
    Linux:x86_64)
        VERUS_ARCHIVE="verus-${VERUS_VERSION}-x86-linux.zip"
        VERUS_ARCHIVE_SHA256="323a44c0d787ce9a788665e1c6922360c44a72d1b9696359ec4f7bf5fbbc63e6"
        VERUS_DIRECTORY="verus-x86-linux"
        ;;
    *)
        echo "unsupported Verus runner platform: $PLATFORM $ARCHITECTURE" >&2
        echo "supported platforms: Darwin arm64, Linux x86_64" >&2
        exit 1
        ;;
esac

TASK_TEMP_BASE=${TMPDIR:-/tmp}
VERUS_CACHE_ROOT=${ACTIVECHAIN_VERUS_CACHE_DIR:-"$TASK_TEMP_BASE/activechain-verus-${VERUS_VERSION}"}
VERUS_ARCHIVE_PATH="$VERUS_CACHE_ROOT/$VERUS_ARCHIVE"
VERUS_UNPACK_ROOT="$VERUS_CACHE_ROOT/unpacked-$VERUS_ARCHIVE_SHA256"
VERUS_BINARY="$VERUS_UNPACK_ROOT/$VERUS_DIRECTORY/verus"
VERUS_BUILD_ROOT="$VERUS_CACHE_ROOT/verified-target"
PARITY_TARGET_ROOT="$VERUS_CACHE_ROOT/parity-target"
VERUS_DOWNLOAD_URL="https://github.com/verus-lang/verus/releases/download/$VERUS_RELEASE_TAG/$VERUS_ARCHIVE"

mkdir -p "$VERUS_CACHE_ROOT"

sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        echo "neither shasum nor sha256sum is available" >&2
        exit 1
    fi
}

if [ ! -f "$VERUS_ARCHIVE_PATH" ]; then
    VERUS_PARTIAL_PATH="$VERUS_ARCHIVE_PATH.partial.$$"
    curl --proto '=https' --tlsv1.2 --fail --location --retry 3 \
        --output "$VERUS_PARTIAL_PATH" "$VERUS_DOWNLOAD_URL"
    PARTIAL_SHA256=$(sha256_file "$VERUS_PARTIAL_PATH")
    if [ "$PARTIAL_SHA256" != "$VERUS_ARCHIVE_SHA256" ]; then
        echo "Verus archive checksum mismatch" >&2
        echo "expected: $VERUS_ARCHIVE_SHA256" >&2
        echo "actual:   $PARTIAL_SHA256" >&2
        exit 1
    fi
    mv "$VERUS_PARTIAL_PATH" "$VERUS_ARCHIVE_PATH"
fi

ARCHIVE_SHA256=$(sha256_file "$VERUS_ARCHIVE_PATH")
if [ "$ARCHIVE_SHA256" != "$VERUS_ARCHIVE_SHA256" ]; then
    echo "cached Verus archive checksum mismatch: $VERUS_ARCHIVE_PATH" >&2
    echo "expected: $VERUS_ARCHIVE_SHA256" >&2
    echo "actual:   $ARCHIVE_SHA256" >&2
    exit 1
fi

if [ ! -x "$VERUS_BINARY" ]; then
    mkdir -p "$VERUS_UNPACK_ROOT"
    unzip -q -o "$VERUS_ARCHIVE_PATH" -d "$VERUS_UNPACK_ROOT"
fi

VERUS_VERSION_OUTPUT=$("$VERUS_BINARY" --version)
printf '%s\n' "$VERUS_VERSION_OUTPUT" | grep -F "Version: $VERUS_VERSION" >/dev/null

mkdir -p "$VERUS_BUILD_ROOT" "$PARITY_TARGET_ROOT"
(
    cd "$VERUS_BUILD_ROOT"
    "$VERUS_BINARY" "$SCRIPT_DIR/activechain_arithmetic.rs" \
        --no-cheating \
        --compile \
        --out-dir "$VERUS_BUILD_ROOT" \
        --rlimit 30 \
        --time
    "$VERUS_BUILD_ROOT/activechain_arithmetic"
)

CARGO_TARGET_DIR="$PARITY_TARGET_ROOT" cargo run \
    --manifest-path "$SCRIPT_DIR/parity/Cargo.toml" \
    --locked \
    --quiet

printf '%s\n' \
    "Verus $VERUS_VERSION ($VERUS_RELEASE_COMMIT) arithmetic verification and production parity passed."
