#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"
python3 - <<'PY'
import hashlib, json
from pathlib import Path
manifest = json.loads(Path('distribution/anyidentity/source.json').read_text())
root = Path('vendor/AnyIdentity')
for name, expected in manifest['files'].items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
        raise SystemExit(f'AnyIdentity source differs from pinned revision: {name}')
print('Verified AnyIdentity source revision ' + manifest['revision'])
PY
stamp="$repo_root/vendor/AnyIdentity/Artifacts/source.sha256"
expected=$(cat distribution/anyidentity/source.json scripts/build-anyidentity.sh | shasum -a 256 | awk '{print $1}')
if [[ ${1:-} != --force && -f "$stamp" && $(cat "$stamp") == "$expected" &&
      -f vendor/AnyIdentity/Artifacts/CAnyIdentity.xcframework/Info.plist ]]; then
  exit 0
fi
# The upstream builder uses its own target paths and invalidates only its SwiftPM cache.
env -u CARGO_TARGET_DIR -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
  bash vendor/AnyIdentity/scripts/build-rust.sh --all
# Xcode copies static-library XCFramework headers into one shared include directory.
# Package AnyIdentity as a static framework so its module map cannot collide with
# ActiveChainWallet's module map. The pinned upstream sources remain unchanged.
python3 - <<'PY'
import plistlib, shutil
from pathlib import Path
root = Path('vendor/AnyIdentity/Artifacts/CAnyIdentity.xcframework')
info = plistlib.loads((root / 'Info.plist').read_bytes())
for library in info['AvailableLibraries']:
    folder = root / library['LibraryIdentifier']
    framework = folder / 'CAnyIdentity.framework'
    framework.mkdir()
    shutil.move(str(folder / library['LibraryPath']), framework / 'CAnyIdentity')
    shutil.move(str(folder / library['HeadersPath']), framework / 'Headers')
    (framework / 'Headers/module.modulemap').unlink()
    (framework / 'Modules').mkdir()
    (framework / 'Modules/module.modulemap').write_text(
        'framework module CAnyIdentity {\n  umbrella header "anyidentity.h"\n  export *\n}\n')
    (framework / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': 'dev.activechain.CAnyIdentity', 'CFBundleName': 'CAnyIdentity',
        'CFBundleExecutable': 'CAnyIdentity', 'CFBundlePackageType': 'FMWK',
        'CFBundleShortVersionString': '0.1.0', 'CFBundleVersion': '1',
    }))
    if library['SupportedPlatform'] == 'macos':
        version = framework / 'Versions/A'
        (version / 'Resources').mkdir(parents=True)
        shutil.move(str(framework / 'Info.plist'), version / 'Resources/Info.plist')
        for name in ['CAnyIdentity', 'Headers', 'Modules']:
            shutil.move(str(framework / name), version / name)
            (framework / name).symlink_to('Versions/Current/' + name)
        (framework / 'Resources').symlink_to('Versions/Current/Resources')
        (framework / 'Versions/Current').symlink_to('A')
    library['LibraryPath'] = 'CAnyIdentity.framework'
    library['BinaryPath'] = 'CAnyIdentity.framework/CAnyIdentity'
    del library['HeadersPath']
(root / 'Info.plist').write_bytes(plistlib.dumps(info))
PY
swift package --package-path "$repo_root/mobile/ios/ActiveChainWallet" clean
printf '%s\n' "$expected" > "$stamp"
