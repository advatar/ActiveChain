#!/usr/bin/env python3
"""Guard the Kanalen endpoint migration without changing its chain identity."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class KanalenDomainConfigurationTests(unittest.TestCase):
    def test_manifest_separates_identity_from_service_endpoints(self) -> None:
        manifest = json.loads((ROOT / "deploy/networks/kanalen.json").read_text())
        hostnames = manifest["hostnames"]

        self.assertEqual(hostnames["domain"], "kanalen.activechain.dev")
        self.assertEqual(hostnames["rpc"], "rpc.kanalen.actum.network")
        self.assertEqual(hostnames["anchor"], "anchor.kanalen.actum.network")
        self.assertEqual(hostnames["verify"], "verify.kanalen.actum.network")
        self.assertEqual(hostnames["delivery"], "delivery.kanalen.actum.network")

    def test_runtime_environment_preserves_chain_id_input(self) -> None:
        environment = (ROOT / "deploy/kanalen/network.env").read_text()

        self.assertIn("ACTIVECHAIN_NETWORK_DOMAIN=kanalen.activechain.dev\n", environment)
        self.assertIn("ACTIVECHAIN_RPC_DOMAIN=rpc.kanalen.actum.network\n", environment)
        self.assertIn("ACTIVECHAIN_ANCHOR_DOMAIN=anchor.kanalen.actum.network\n", environment)
        self.assertIn("ACTIVECHAIN_WORK_PROOF_DOMAIN=verify.kanalen.actum.network\n", environment)
        self.assertIn("ACTIVECHAIN_WORK_DELIVERY_DOMAIN=delivery.kanalen.actum.network\n", environment)

    def test_caddy_owns_new_http_names_and_traefik_owns_rpc(self) -> None:
        caddy = (ROOT / "deploy/kanalen/gateway/kanalen.Caddyfile").read_text()
        dynamic = (ROOT / "deploy/kanalen/gateway/dynamic.yml").read_text()

        for hostname in (
            "kanalen.actum.network",
            "anchor.kanalen.actum.network",
            "verify.kanalen.actum.network",
            "delivery.kanalen.actum.network",
        ):
            self.assertIn(hostname, caddy)
        self.assertIn("HostSNI(`rpc.kanalen.actum.network`)", dynamic)
        self.assertNotIn("HostSNI(`anchor.kanalen.actum.network`)", dynamic)
        self.assertNotIn("HostSNI(`verify.kanalen.actum.network`)", dynamic)


if __name__ == "__main__":
    unittest.main()
