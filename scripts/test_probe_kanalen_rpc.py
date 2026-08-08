#!/usr/bin/env python3
"""Offline regression tests for the exact public Kanalen RPC status boundary."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).with_name("probe-kanalen-rpc.py")
SPEC = spec_from_file_location("probe_kanalen_rpc", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
probe = module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)

PUBLIC_STATUS = bytes.fromhex(
    "010a0001910100"
    "b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0"
    "b095e6cfe944bd2c9f6535b4c927782f1"
    "466ba6bb38dbf6c17a67994ee7c0edcc0858755c937f7c519b9cc144c2b64290"
    "282174ad6899466aeb7078da49a998be"
    "0000000000000001"
    "00000002"
    "0000000000004587"
    "000000006a778641"
    "000000006a778641"
    "000000000000012c"
    "00"
    "02"
    "01"
    "02"
)


class KanalenProbeTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
