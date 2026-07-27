#!/usr/bin/env python3
"""Probe the TLS-terminated Kanalen RPC status envelope."""
import socket
import ssl
import struct
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "rpc.kanalen.activechain.dev"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
request = bytes.fromhex("0000000600a000010100")

context = ssl.create_default_context()
with socket.create_connection((host, port), timeout=10) as raw:
    with context.wrap_socket(raw, server_hostname=host) as conn:
        conn.sendall(request)
        prefix = conn.recv(4)
        if len(prefix) != 4:
            raise SystemExit("short RPC frame header")
        length = struct.unpack(">I", prefix)[0]
        body = b""
        while len(body) < length:
            chunk = conn.recv(length - len(body))
            if not chunk:
                raise SystemExit("truncated RPC status frame")
            body += chunk

if body[:4] != bytes.fromhex("00a10001") or body[4] == 0:
    raise SystemExit("unexpected RPC status envelope")
print(f"{host}:{port} TLS RPC status reachable; frame_bytes={length}")
