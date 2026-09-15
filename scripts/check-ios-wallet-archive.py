#!/usr/bin/env python3
"""Check App Store metadata and symbols in an ActiveChain Wallet archive."""

import plistlib
import re
import subprocess
import sys
from pathlib import Path


def uuids(path: Path) -> set[str]:
    output = subprocess.check_output(["xcrun", "dwarfdump", "--uuid", str(path)], text=True)
    return set(re.findall(r"UUID: ([0-9A-F-]+)", output))


def check(archive: Path) -> None:
    app = archive / "Products/Applications/ActiveChainWallet.app"
    framework = app / "Frameworks/CAnyIdentity.framework"
    info = plistlib.loads((framework / "Info.plist").read_bytes())
    minimum = info.get("MinimumOSVersion")
    if not isinstance(minimum, str) or not re.fullmatch(r"\d+(?:\.\d+)*", minimum):
        raise ValueError("CAnyIdentity MinimumOSVersion is missing or invalid")
    if int(minimum.split(".")[0]) < 8:
        raise ValueError("CAnyIdentity MinimumOSVersion must be iOS 8.0 or newer")

    binary = framework / "CAnyIdentity"
    dsym = archive / "dSYMs/CAnyIdentity.framework.dSYM"
    dwarf = dsym / "Contents/Resources/DWARF/CAnyIdentity"
    if not dwarf.is_file() or dwarf.stat().st_size == 0:
        raise ValueError("CAnyIdentity archive dSYM is missing")
    if not uuids(binary) or uuids(binary) != uuids(dsym):
        raise ValueError("CAnyIdentity archive dSYM UUID does not match the embedded binary")

    app_dsym = archive / "dSYMs/ActiveChainWallet.app.dSYM"
    debug_info = subprocess.check_output(
        ["xcrun", "dwarfdump", "--debug-info", str(app_dsym)], text=True
    )
    if "anyidentity_core" not in debug_info:
        raise ValueError("the app dSYM is missing statically linked AnyIdentity symbols")
    print(f"Wallet archive has iOS {minimum} metadata and matching AnyIdentity symbols")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-ios-wallet-archive.py <archive.xcarchive>")
    try:
        check(Path(sys.argv[1]))
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        raise SystemExit(str(error)) from error
