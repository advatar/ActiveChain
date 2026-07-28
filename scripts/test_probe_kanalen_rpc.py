#!/usr/bin/env python3
"""Unit tests for the bounded canonical Kanalen RPC status probe."""

import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SCRIPT = Path(__file__).with_name("probe-kanalen-rpc.py")
SPEC = importlib.util.spec_from_file_location("probe_kanalen_rpc", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


def uleb128(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def status_envelope(
    *,
    chain_id: bytes = probe.EXPECTED_CHAIN_ID,
    genesis: bytes = probe.EXPECTED_GENESIS,
    protocol: int = 1,
    schema: int = 2,
    finalized_at: int = 1_785_233_700,
    served_at: int = 1_785_233_703,
    maximum_staleness: int = 300,
    health: int = 0,
    proofs: bytes = bytes((1, 2)),
) -> bytes:
    body = b"".join(
        (
            b"\x00",
            chain_id,
            genesis,
            struct.pack(">Q", protocol),
            struct.pack(">I", schema),
            struct.pack(">Q", 5_794),
            struct.pack(">Q", finalized_at),
            struct.pack(">Q", served_at),
            struct.pack(">Q", maximum_staleness),
            bytes((health,)),
            uleb128(len(proofs)),
            proofs,
        )
    )
    return bytes.fromhex("00a10001") + uleb128(len(body)) + body


class DecodeStatusTests(unittest.TestCase):
    def test_exact_kanalen_status_decodes(self) -> None:
        status = probe.decode_status_envelope(status_envelope())
        self.assertEqual(status.finalized_height, 5_794)
        self.assertEqual(status.health_name, "healthy")
        self.assertEqual(status.supported_proofs, (1, 2))

    def test_network_identity_and_revisions_are_pinned(self) -> None:
        invalid = (
            status_envelope(chain_id=bytes((0x44,)) * 48),
            status_envelope(genesis=bytes((0x55,)) * 48),
            status_envelope(protocol=2),
            status_envelope(schema=1),
        )
        for envelope in invalid:
            with self.subTest(envelope=envelope[5:12]):
                with self.assertRaises(probe.ProbeError):
                    probe.decode_status_envelope(envelope)

    def test_health_and_proof_claims_are_canonical(self) -> None:
        invalid = (
            status_envelope(health=1),
            status_envelope(proofs=b""),
            status_envelope(proofs=bytes((2, 1))),
            status_envelope(proofs=bytes((1, 1))),
            status_envelope(proofs=bytes((4,))),
        )
        for envelope in invalid:
            with self.subTest(envelope=envelope[-5:]):
                with self.assertRaises(probe.ProbeError):
                    probe.decode_status_envelope(envelope)

    def test_truncation_trailing_bytes_and_nonminimal_lengths_fail(self) -> None:
        envelope = status_envelope()
        invalid = (
            envelope[:-1],
            envelope + b"\x00",
            envelope[:4] + bytes((envelope[4] | 0x80, 0)) + envelope[5:],
        )
        for candidate in invalid:
            with self.subTest(length=len(candidate)):
                with self.assertRaises(probe.ProbeError):
                    probe.decode_status_envelope(candidate)


if __name__ == "__main__":
    unittest.main()
