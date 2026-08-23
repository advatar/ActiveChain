#!/usr/bin/env python3
"""Private localhost HTTP adapter for the Kanalen PoW qualification.

Bearer values are read inside this process and never passed through argv or
stdout. Only bounded backend JSON responses are emitted.
"""

import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

ROOT = Path(os.environ.get("ACTIVECHAIN_KANALEN_ROOT", Path.home() / "activechain-deploy/kanalen"))
REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_RESPONSE = 64 * 1024


def private_token(path: Path) -> str:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_mode & 0o077:
        raise ValueError("private bearer file rejected")
    token = path.read_text("ascii").strip()
    if not 32 <= len(token) <= 256 or not token.isprintable():
        raise ValueError("private bearer value rejected")
    return token


def artifact(path: Path) -> bytes:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or not 0 < metadata.st_size <= 2 * 1024 * 1024:
        raise ValueError("bounded qualification artifact rejected")
    return path.read_bytes()


def anchor_bytes(path: Path) -> bytes:
    value = json.loads(artifact(path))
    encoded = value.get("anchor_request_envelope_hex") if isinstance(value, dict) else None
    if (
        not isinstance(encoded, str)
        or not encoded
        or len(encoded) > 512 * 1024
        or len(encoded) % 2
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        raise ValueError("qualification artifact has no canonical anchor request")
    return bytes.fromhex(encoded)


def post(url: str, token_path: Path, body: bytes, content_type: str, request_id: str) -> dict:
    if not REQUEST_ID.fullmatch(request_id):
        raise ValueError("request ID rejected")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {private_token(token_path)}",
            "Content-Type": content_type,
            "X-Actum-Request-Id": request_id,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as error:
        payload = error.read(MAX_RESPONSE + 1)
    if len(payload) > MAX_RESPONSE:
        raise ValueError("backend response exceeded qualification bound")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("backend returned a malformed qualification response")
    return value


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit("usage: qualification-http.py <delivery|anchor|verify|extract-anchor> ...")
    command = sys.argv[1]
    path = Path(sys.argv[2])
    if command == "extract-anchor" and len(sys.argv) == 4:
        output = Path(sys.argv[3])
        if output.exists():
            raise ValueError("refusing to overwrite anchor request output")
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(anchor_bytes(path))
            stream.flush()
            os.fsync(stream.fileno())
        return 0
    if len(sys.argv) != 4:
        raise ValueError("qualification HTTP command requires an artifact and request ID")
    request_id = sys.argv[3]
    if command == "delivery":
        value = post(
            "http://127.0.0.1:49158/v1/deliveries",
            ROOT / "work-delivery/bearer.token",
            artifact(path),
            "application/octet-stream",
            request_id,
        )
    elif command == "anchor":
        value = post(
            "http://127.0.0.1:49156/v1/anchors",
            ROOT / "anchor/bearer.token",
            anchor_bytes(path),
            "application/octet-stream",
            request_id,
        )
    elif command == "verify":
        value = post(
            "http://127.0.0.1:49157/v1/proofs/verify",
            ROOT / "work-proof/bearer.token",
            artifact(path),
            "application/vnd.actum.work-proof.v1+json",
            request_id,
        )
    else:
        raise ValueError("unknown qualification HTTP command")
    print(json.dumps(value, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
