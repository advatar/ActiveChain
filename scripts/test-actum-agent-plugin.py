#!/usr/bin/env python3
"""Deterministic structural and lifecycle tests for the Actum Agent Plugin."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "actum-node"
CONTROL = PLUGIN / "skills" / "actum-node" / "scripts" / "actum-node"


class PluginStructureTests(unittest.TestCase):
    def test_manifest_and_mcp_use_v1_closed_fields(self) -> None:
        manifest = json.loads((PLUGIN / "plugin.json").read_text())
        self.assertEqual(manifest["$schema"], "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json")
        self.assertEqual(manifest["name"], "actum-node")
        self.assertLessEqual(set(manifest), {"$schema", "name", "version", "description", "author", "homepage", "repository", "license", "keywords", "extensions"})
        mcp = json.loads((PLUGIN / "mcp.json").read_text())
        self.assertEqual(mcp["$schema"], "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json")
        server = mcp["mcpServers"]["actum"]
        self.assertEqual(server["type"], "stdio")
        self.assertTrue(server["command"].startswith("./"))
        self.assertEqual(server["cwd"], "${PLUGIN_ROOT}")

    def test_codex_manifest_reuses_portable_components(self) -> None:
        manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text())
        self.assertEqual(manifest["name"], "actum-node")
        self.assertEqual(manifest["skills"], "./skills/")
        self.assertEqual(manifest["mcpServers"], "./.mcp.json")
        mcp = json.loads((PLUGIN / ".mcp.json").read_text())
        self.assertEqual(
            mcp["mcpServers"]["actum"]["command"],
            "./bin/activechain-mcp",
        )

    def test_skill_frontmatter_matches_directory(self) -> None:
        skill = (PLUGIN / "skills" / "actum-node" / "SKILL.md").read_text()
        self.assertTrue(skill.startswith("---\nname: actum-node\n"))
        self.assertIn("\ndescription:", skill)


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.data = root / "data"
        self.bins = root / "bin"
        self.bins.mkdir()
        self.snapshot = root / "rpc.snapshot"
        self.snapshot.write_bytes(b"test")
        self._binary("activechain-rpc-node", "trap 'exit 0' TERM INT\necho started\nwhile :; do sleep 1; done")
        self._binary("activechain-rpc-probe", "printf 'chain_id=aa genesis=bb finalized_height=7 health=Healthy\\n'")
        self.env = {**os.environ, "PLUGIN_DATA": str(self.data), "ACTUM_BIN_DIR": str(self.bins), "ACTIVECHAIN_FAUCET_ENABLED": "true"}

    def tearDown(self) -> None:
        subprocess.run([str(CONTROL), "stop", "--timeout", "2"], env=self.env, capture_output=True)
        self.temporary.cleanup()

    def _binary(self, name: str, body: str) -> None:
        path = self.bins / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def run_control(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(CONTROL), *arguments], env=self.env, text=True, capture_output=True, check=check)

    def test_start_status_logs_query_and_stop(self) -> None:
        started = json.loads(self.run_control("start", "--snapshot", str(self.snapshot)).stdout)
        self.assertEqual(started["status"], "running")
        status_value = json.loads(self.run_control("status").stdout)
        self.assertEqual(status_value["status"], "running")
        log_output = ""
        for _ in range(20):
            log_output = self.run_control("logs", "--lines", "1").stdout.strip()
            if log_output:
                break
            time.sleep(0.05)
        self.assertEqual(log_output, "started")
        query = json.loads(self.run_control("query", "--address", "127.0.0.1:9").stdout)
        self.assertIn("finalized_height=7", query["response"])
        stopped = json.loads(self.run_control("stop", "--timeout", "2").stdout)
        self.assertTrue(stopped["changed"])

    def test_public_bind_and_foreign_pid_fail_closed(self) -> None:
        public = self.run_control("start", "--snapshot", str(self.snapshot), "--bind", "0.0.0.0:49151", check=False)
        self.assertNotEqual(public.returncode, 0)
        self.data.mkdir(exist_ok=True)
        (self.data / "rpc-node.json").write_text(json.dumps({"pid": os.getpid(), "start_time": "wrong", "command": "wrong"}))
        stopped = self.run_control("stop", check=False)
        self.assertNotEqual(stopped.returncode, 0)
        self.assertTrue((self.data / "rpc-node.json").exists())


if __name__ == "__main__":
    unittest.main()
