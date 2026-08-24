#!/usr/bin/env python3
"""Unit tests for the bounded canonical Kanalen RPC status probe."""

import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).with_name("probe-kanalen-rpc.py")
SPEC = importlib.util.spec_from_file_location("probe_kanalen_rpc", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)

PUBLIC_STATUS = bytes.fromhex(
    "010a0004910100"
    "b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0"
    "b095e6cfe944bd2c9f6535b4c927782f1"
    "a836c4d201cda6ba33a01aa48011cf5f4d6acdfd1ec409d322dc1b56ed3552a2"
    "5dcb158e0b1ec0352728653d315d477c"
    "0000000000000001"
    "00000004"
    "0000000000004587"
    "000000006a778641"
    "000000006a778641"
    "000000000000012c"
    "00"
    "02"
    "01"
    "02"
)


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
    schema: int = 4,
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
    return bytes.fromhex("010a0004") + uleb128(len(body)) + body


class DecodeStatusTests(unittest.TestCase):
    def test_status_request_uses_current_canonical_rpc_request_tag(self) -> None:
        self.assertEqual(probe.STATUS_REQUEST, bytes.fromhex("00000006010700030100"))

    def test_exact_kanalen_status_decodes(self) -> None:
        status = probe.decode_status_envelope(status_envelope())
        self.assertEqual(status.finalized_height, 5_794)
        self.assertEqual(status.health_name, "healthy")
        self.assertEqual(status.supported_proofs, (1, 2))

    def test_public_status_fixture_matches_immutable_identity(self) -> None:
        status = probe.decode_status_envelope(PUBLIC_STATUS)
        self.assertEqual(status.chain_id, probe.EXPECTED_CHAIN_ID)
        self.assertEqual(status.genesis, probe.EXPECTED_GENESIS)
        self.assertEqual(status.finalized_height, 0x4587)
        self.assertEqual(status.health_name, "healthy")
        self.assertEqual(status.supported_proofs, (1, 2))

    def test_genesis_substitution_fails_closed(self) -> None:
        substituted = bytearray(PUBLIC_STATUS)
        substituted[55] ^= 1
        with self.assertRaisesRegex(probe.ProbeError, "genesis commitment mismatch"):
            probe.decode_status_envelope(bytes(substituted))

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
