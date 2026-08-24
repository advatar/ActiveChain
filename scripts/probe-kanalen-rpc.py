#!/usr/bin/env python3
"""Verify the canonical TLS RPC status advertised by the Kanalen testnet."""

from __future__ import annotations

from dataclasses import dataclass
import socket
import ssl
import struct
import sys


DEFAULT_HOST = "rpc.kanalen.actum.network"
DEFAULT_PORT = 443
EXPECTED_CHAIN_ID = bytes.fromhex(
    "b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0"
    "b095e6cfe944bd2c9f6535b4c927782f1"
)
EXPECTED_GENESIS = bytes.fromhex(
    "f600eb4a562a3acd2bd82e46fa8ee063217153f827af12300c35fcb1b75fc96a"
    "b5650477691a6ce1b4350a314e5dbca4"
)
EXPECTED_PROTOCOL_REVISION = 1
EXPECTED_RPC_SCHEMA_REVISION = 4
MAXIMUM_FRAME_LENGTH = 4 * 1024 * 1024
MAXIMUM_STATUS_BODY_LENGTH = 151
STATUS_REQUEST = bytes.fromhex("00000006010700030100")
PROOF_NAMES = (
    "state-sparse-merkle",
    "finality-certificate",
    "receipt-commitment",
    "data-availability",
)


class ProbeError(ValueError):
    """Raised when a response is not the exact bounded canonical Kanalen status."""


@dataclass(frozen=True)
class RpcStatus:
    chain_id: bytes
    genesis: bytes
    protocol_revision: int
    schema_revision: int
    finalized_height: int
    finalized_at: int
    served_at: int
    maximum_staleness: int
    health: int
    supported_proofs: tuple[int, ...]

    @property
    def health_name(self) -> str:
        return ("healthy", "stale")[self.health]


class Decoder:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def read(self, count: int) -> bytes:
        if count < 0 or self.remaining < count:
            raise ProbeError("truncated RPC status")
        value = self.data[self.offset : self.offset + count]
        self.offset += count
        return value

    def uint(self, count: int) -> int:
        return int.from_bytes(self.read(count), "big")

    def length(self, maximum: int) -> int:
        value = 0
        shift = 0
        for count in range(1, 6):
            byte = self.uint(1)
            payload = byte & 0x7F
            if shift == 28 and payload > 0x0F:
                raise ProbeError("canonical length overflows u32")
            value |= payload << shift
            if byte & 0x80 == 0:
                if count != 1 and payload == 0:
                    raise ProbeError("non-minimal canonical length")
                if value > maximum:
                    raise ProbeError("canonical length exceeds its bound")
                return value
            shift += 7
        raise ProbeError("canonical length overflows u32")


def decode_status_envelope(envelope: bytes) -> RpcStatus:
    decoder = Decoder(envelope)
    if decoder.uint(2) != 0x010A:
        raise ProbeError("unexpected RPC response type")
    if decoder.uint(2) != 1:
        raise ProbeError("unexpected RPC response envelope schema")
    body_length = decoder.length(MAXIMUM_STATUS_BODY_LENGTH)
    if body_length != decoder.remaining:
        raise ProbeError("RPC status body length mismatch")
    if decoder.uint(1) != 0:
        raise ProbeError("RPC response is not a status")

    chain_id = decoder.read(48)
    genesis = decoder.read(48)
    protocol_revision = decoder.uint(8)
    schema_revision = decoder.uint(4)
    finalized_height = decoder.uint(8)
    finalized_at = decoder.uint(8)
    served_at = decoder.uint(8)
    maximum_staleness = decoder.uint(8)
    health = decoder.uint(1)
    proof_count = decoder.length(8)
    supported_proofs = tuple(decoder.uint(1) for _ in range(proof_count))

    if decoder.remaining:
        raise ProbeError("trailing RPC status bytes")
    if chain_id != EXPECTED_CHAIN_ID:
        raise ProbeError("Kanalen chain ID mismatch")
    if genesis != EXPECTED_GENESIS:
        raise ProbeError("Kanalen genesis commitment mismatch")
    if protocol_revision != EXPECTED_PROTOCOL_REVISION:
        raise ProbeError("Kanalen protocol revision mismatch")
    if schema_revision != EXPECTED_RPC_SCHEMA_REVISION:
        raise ProbeError("Kanalen RPC schema revision mismatch")
    if finalized_at > served_at:
        raise ProbeError("RPC finalized time is later than served time")
    if maximum_staleness == 0:
        raise ProbeError("RPC maximum staleness is zero")
    expected_health = 1 if served_at - finalized_at > maximum_staleness else 0
    if health != expected_health:
        raise ProbeError("RPC health does not match its staleness claim")
    if not supported_proofs:
        raise ProbeError("RPC status advertises no proof kinds")
    if any(proof > 3 for proof in supported_proofs):
        raise ProbeError("RPC status advertises an unknown proof kind")
    if any(left >= right for left, right in zip(supported_proofs, supported_proofs[1:])):
        raise ProbeError("RPC proof kinds are not strictly ordered")

    return RpcStatus(
        chain_id=chain_id,
        genesis=genesis,
        protocol_revision=protocol_revision,
        schema_revision=schema_revision,
        finalized_height=finalized_height,
        finalized_at=finalized_at,
        served_at=served_at,
        maximum_staleness=maximum_staleness,
        health=health,
        supported_proofs=supported_proofs,
    )


def receive_exact(connection: ssl.SSLSocket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = connection.recv(count - len(chunks))
        if not chunk:
            raise ProbeError("truncated RPC status frame")
        chunks.extend(chunk)
    return bytes(chunks)


def query_status(host: str, port: int) -> tuple[RpcStatus, int, str]:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((host, port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            connection.settimeout(10)
            connection.sendall(STATUS_REQUEST)
            length = struct.unpack(">I", receive_exact(connection, 4))[0]
            if length == 0 or length > MAXIMUM_FRAME_LENGTH:
                raise ProbeError("invalid RPC frame length")
            envelope = receive_exact(connection, length)
            status = decode_status_envelope(envelope)
            return status, length, connection.version() or "unknown TLS"


def main(arguments: list[str]) -> int:
    host = arguments[0] if arguments else DEFAULT_HOST
    port = int(arguments[1]) if len(arguments) > 1 else DEFAULT_PORT
    if len(arguments) > 2:
        raise ProbeError("usage: probe-kanalen-rpc.py [host [port]]")
    status, frame_length, tls_version = query_status(host, port)
    proofs = ",".join(PROOF_NAMES[value] for value in status.supported_proofs)
    print(
        f"{host}:{port} Kanalen RPC verified; tls={tls_version}; "
        f"chain={status.chain_id.hex()}; genesis={status.genesis.hex()}; "
        f"protocol={status.protocol_revision}; schema={status.schema_revision}; "
        f"height={status.finalized_height}; health={status.health_name}; "
        f"proofs={proofs}; frame_bytes={frame_length}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ProbeError, ValueError) as error:
        raise SystemExit(f"Kanalen RPC probe failed: {error}") from error
