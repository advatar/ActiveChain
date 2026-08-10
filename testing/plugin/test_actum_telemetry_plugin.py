#!/usr/bin/env python3
import importlib.util, json, os, subprocess, tempfile, threading, unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/"plugins/actum-telemetry/bin/actum-telemetry-mcp"
spec=importlib.util.spec_from_loader("actum_telemetry_mcp",SourceFileLoader("actum_telemetry_mcp",str(SCRIPT)))
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

class Reply:
    def __init__(self,value): self.value=value
    def __enter__(self): return self
    def __exit__(self,*_): return False
    def read(self,_): return json.dumps(self.value).encode()

class TelemetryPluginTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.env=patch.dict(os.environ,{"ACTUM_PLUGIN_DATA":self.temp.name,"ACTUM_TELEMETRY_CAPABILITY":"secret-capability","ACTUM_CHAIN_ID":"1"*96,"ACTUM_GENESIS_COMMITMENT":"2"*96},clear=True); self.env.start(); self.addCleanup(self.env.stop)
        self.project="3"*96; self.policy="4"*96
    def auth(self,request="auth-1",capability="secret-capability"):
        return {"capability":capability,"request_id":request,"project_id":self.project,"policy_id":self.policy,"revision":1,"purpose":"proof of developer contribution","categories":["build_test"],"valid_from_ms":1,"retain_until_ms":10_000}
    def authorize(self): return module.call("telemetry.authorize",self.auth())
    def test_portable_and_codex_manifests_share_the_bounded_components(self):
        plugin=ROOT/"plugins/actum-telemetry"
        manifest=json.loads((plugin/"plugin.json").read_text())
        self.assertEqual(manifest["$schema"],"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json")
        self.assertLessEqual(set(manifest),{"$schema","name","version","description","author","homepage","repository","license","keywords","extensions"})
        portable=json.loads((plugin/"mcp.json").read_text())["mcpServers"]["actum-telemetry"]
        self.assertEqual(portable["command"],"./bin/actum-telemetry-mcp"); self.assertEqual(portable["cwd"],"${PLUGIN_ROOT}")
        codex=json.loads((plugin/".codex-plugin/plugin.json").read_text()); self.assertEqual(codex["skills"],"./skills/"); self.assertEqual(codex["mcpServers"],"./.mcp.json")
    def test_absent_authorization_is_paused_and_credentials_are_not_reported(self):
        result=module.call("telemetry.status",{"project_id":self.project})
        self.assertEqual(result["status"],"not_authorized"); self.assertTrue(result["paused"])
        self.assertNotIn("secret-capability",json.dumps(result))
    def test_authorize_requires_capability_and_defaults_paused(self):
        with self.assertRaises(PermissionError): module.call("telemetry.authorize",self.auth(capability="wrong"))
        result=self.authorize(); self.assertEqual(result["status"],"authorized"); self.assertTrue(result["paused"])
        self.assertNotIn("secret-capability",Path(module.state_path()).read_text())
    def test_pause_resume_is_durable_and_idempotent(self):
        self.authorize(); args={"capability":"secret-capability","request_id":"resume-1","project_id":self.project}
        first=module.call("telemetry.resume",args); second=module.call("telemetry.resume",args)
        self.assertFalse(first["duplicate"]); self.assertTrue(second["duplicate"]); self.assertFalse(module.load_state()["paused"][self.project])
    def test_duplicate_request_with_other_arguments_is_rejected(self):
        self.authorize(); args={"capability":"secret-capability","request_id":"same","project_id":self.project}
        module.call("telemetry.pause",args)
        with self.assertRaises(ValueError): module.call("telemetry.resume",args)
    def test_unknown_fields_are_rejected(self):
        args=self.auth(); args["source"]="private"
        with self.assertRaises(ValueError): module.call("telemetry.authorize",args)
    def test_wrong_chain_delivery_fails_without_registration(self):
        self.authorize(); artifact=Path(self.temp.name)/"proof.bin"; artifact.write_bytes(b"proof")
        os.environ["ACTUM_DELIVERY_WEBHOOK"]="https://delivery.example/submit"
        args={"capability":"secret-capability","request_id":"deliver-1","project_id":self.project,"artifact_path":str(artifact)}
        with patch.object(module,"urlopen",return_value=Reply({"status":"delivered","chain_id":"9"*96,"genesis_commitment":"2"*96})):
            with self.assertRaises(RuntimeError): module.call("work.deliver",args)
        self.assertNotIn("deliver-1",module.load_state()["requests"])
    def test_anchor_uses_protected_backend_credential_without_exposing_it(self):
        self.authorize(); artifact=Path(self.temp.name)/"anchor.bin"; artifact.write_bytes(b"anchor")
        token=Path(self.temp.name)/"anchor-token"; token.write_text("abcdefghijklmnopqrstuvwxyz012345"); token.chmod(0o600)
        os.environ["ACTUM_ANCHOR_URL"]="https://anchor.example/v1/anchors"; os.environ["ACTUM_ANCHOR_BEARER_TOKEN_FILE"]=str(token)
        args={"capability":"secret-capability","request_id":"anchor-1","project_id":self.project,"artifact_path":str(artifact)}
        captured=[]
        def respond(request,**_):
            captured.append(request); return Reply({"status":"pending","chain_id":"1"*96,"genesis_commitment":"2"*96,"reference":"5"*96})
        with patch.object(module,"urlopen",side_effect=respond): result=module.call("work.anchor",args)
        self.assertEqual(result["status"],"pending"); self.assertEqual(captured[0].headers["Authorization"],"Bearer abcdefghijklmnopqrstuvwxyz012345")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345",json.dumps(result)); self.assertNotIn("abcdefghijklmnopqrstuvwxyz012345",module.state_path().read_text())
        token.chmod(0o640)
        args["request_id"]="anchor-2"
        with self.assertRaises(RuntimeError): module.call("work.anchor",args)
        token.write_bytes(b"a"*31+b"\0"); token.chmod(0o600); args["request_id"]="anchor-3"
        with self.assertRaises(RuntimeError): module.call("work.anchor",args)
    def test_export_contains_control_metadata_not_evidence(self):
        self.authorize(); args={"capability":"secret-capability","request_id":"export-1","project_id":self.project}
        result=module.call("telemetry.export",args); self.assertFalse(result["evidence_included"])
        exported=json.loads(Path(result["path"]).read_text()); self.assertNotIn("events",exported)

    def test_pause_race_serializes_both_durable_requests(self):
        self.authorize(); barrier=threading.Barrier(3); errors=[]
        def invoke(name,request):
            try:
                barrier.wait(); module.call(name,{"capability":"secret-capability","request_id":request,"project_id":self.project})
            except Exception as error: errors.append(error)
        first=threading.Thread(target=invoke,args=("telemetry.pause","race-pause")); second=threading.Thread(target=invoke,args=("telemetry.resume","race-resume"))
        first.start(); second.start(); barrier.wait(); first.join(); second.join()
        self.assertEqual(errors,[]); state=module.load_state(); self.assertIn("race-pause",state["requests"]); self.assertIn("race-resume",state["requests"]); self.assertIsInstance(state["paused"][self.project],bool)

    def test_timeout_and_malformed_backend_fail_without_receipt(self):
        self.authorize(); artifact=Path(self.temp.name)/"proof.bin"; artifact.write_bytes(b"proof"); os.environ["ACTUM_DELIVERY_WEBHOOK"]="https://delivery.example/submit"
        def arguments(request): return {"capability":"secret-capability","request_id":request,"project_id":self.project,"artifact_path":str(artifact)}
        with patch.object(module,"urlopen",side_effect=TimeoutError):
            with self.assertRaises(RuntimeError): module.call("work.deliver",arguments("timeout"))
        with patch.object(module,"urlopen",return_value=Reply({"chain_id":"1"*96,"genesis_commitment":"2"*96})):
            with self.assertRaises(RuntimeError): module.call("work.deliver",arguments("malformed"))
        state=module.load_state(); self.assertNotIn("timeout",state["requests"]); self.assertNotIn("malformed",state["requests"])

    def test_pending_anchor_refreshes_with_same_idempotency_key_after_restart(self):
        self.authorize(); artifact=Path(self.temp.name)/"anchor.bin"; artifact.write_bytes(b"anchor")
        token=Path(self.temp.name)/"anchor-token"; token.write_text("abcdefghijklmnopqrstuvwxyz012345"); token.chmod(0o600)
        os.environ["ACTUM_ANCHOR_URL"]="https://anchor.example/v1/anchors"; os.environ["ACTUM_ANCHOR_BEARER_TOKEN_FILE"]=str(token)
        args={"capability":"secret-capability","request_id":"anchor-recovery","project_id":self.project,"artifact_path":str(artifact)}
        replies=[Reply({"status":"pending","chain_id":"1"*96,"genesis_commitment":"2"*96,"reference":"5"*96}),Reply({"status":"finalized","chain_id":"1"*96,"genesis_commitment":"2"*96,"reference":"5"*96})]
        with patch.object(module,"urlopen",side_effect=replies) as backend:
            pending=module.call("work.anchor",args)
            self.assertEqual(module.load_state()["requests"]["anchor-recovery"]["result"]["status"],"pending")
            finalized=module.call("work.anchor",args)
        self.assertEqual(pending["status"],"pending"); self.assertFalse(pending["duplicate"])
        self.assertEqual(finalized["status"],"finalized"); self.assertTrue(finalized["duplicate"]); self.assertEqual(backend.call_count,2)
        with patch.object(module,"urlopen") as backend: cached=module.call("work.anchor",args)
        self.assertEqual(cached["status"],"finalized"); self.assertTrue(cached["duplicate"]); backend.assert_not_called()

    def test_delivery_success_does_not_promote_failed_anchor(self):
        self.authorize(); artifact=Path(self.temp.name)/"proof.bin"; artifact.write_bytes(b"proof")
        token=Path(self.temp.name)/"anchor-token"; token.write_text("abcdefghijklmnopqrstuvwxyz012345"); token.chmod(0o600)
        os.environ.update({"ACTUM_DELIVERY_WEBHOOK":"https://delivery.example/submit","ACTUM_ANCHOR_URL":"https://anchor.example/v1/anchors","ACTUM_ANCHOR_BEARER_TOKEN_FILE":str(token)})
        base={"capability":"secret-capability","project_id":self.project,"artifact_path":str(artifact)}
        with patch.object(module,"urlopen",return_value=Reply({"status":"delivered","chain_id":"1"*96,"genesis_commitment":"2"*96,"reference":"delivery"})):
            delivered=module.call("work.deliver",{**base,"request_id":"delivered-only"})
        with patch.object(module,"urlopen",side_effect=TimeoutError):
            with self.assertRaises(RuntimeError): module.call("work.anchor",{**base,"request_id":"anchor-failed"})
        self.assertEqual(delivered["status"],"delivered")
        self.assertNotIn("anchor-failed",module.load_state()["requests"])

    def test_work_verifier_relation_success_never_implies_anchor_or_usage(self):
        self.authorize(); request=Path(self.temp.name)/"verify.json"; request.write_text("{}")
        verifier=Path(self.temp.name)/"verifier"; verifier.write_text("#!/bin/sh\nprintf '%s\\n' '{\"schema\":\"actum.work-proof.verify.result.v1\",\"code\":\"VERIFIED\",\"verified\":true,\"profile\":\"actum.non-overlap.risc0.v1\"}'\n"); verifier.chmod(0o700)
        os.environ["ACTUM_WORK_VERIFIER"]=str(verifier)
        args={"capability":"secret-capability","request_id":"verify-1","project_id":self.project,"artifact_path":str(request)}
        result=module.call("work.verify",args)
        self.assertEqual(result["status"],"relation_verified"); self.assertTrue(result["relation_verified"])
        self.assertFalse(result["anchor_verified"]); self.assertFalse(result["usage_verified"])

    def test_work_verifier_rejects_inconsistent_success_and_backend_failures_are_retryable(self):
        self.authorize(); request=Path(self.temp.name)/"verify.json"; request.write_text("{}")
        verifier=Path(self.temp.name)/"verifier"; verifier.write_text("#!/bin/sh\nprintf '%s\\n' '{\"schema\":\"actum.work-proof.verify.result.v1\",\"code\":\"INVALID\",\"verified\":true,\"profile\":\"actum.non-overlap.risc0.v1\"}'\n"); verifier.chmod(0o700)
        os.environ["ACTUM_WORK_VERIFIER"]=str(verifier)
        args={"capability":"secret-capability","request_id":"verify-invalid","project_id":self.project,"artifact_path":str(request)}
        with self.assertRaises(RuntimeError): module.call("work.verify",args)
        self.assertNotIn("verify-invalid",module.load_state()["requests"])

        os.environ["ACTUM_DELIVERY_WEBHOOK"]="https://delivery.example/submit"
        delivery={"capability":"secret-capability","request_id":"delivery-retry","project_id":self.project,"artifact_path":str(request)}
        for failure in (TimeoutError(),RuntimeError("429"),RuntimeError("500")):
            with patch.object(module,"urlopen",side_effect=failure):
                with self.assertRaises(RuntimeError): module.call("work.deliver",delivery)
        with patch.object(module,"urlopen",return_value=Reply({"status":"delivered","chain_id":"1"*96,"genesis_commitment":"2"*96})):
            recovered=module.call("work.deliver",delivery)
        self.assertEqual(recovered["status"],"delivered"); self.assertFalse(recovered["duplicate"])

    def test_mcp_handshake_lists_all_bounded_tools_without_secret(self):
        frames=[
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}},
            {"jsonrpc":"2.0","method":"notifications/initialized"},
            {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},
        ]
        completed=subprocess.run([str(SCRIPT)],input="".join(json.dumps(frame)+"\n" for frame in frames),text=True,capture_output=True,env=os.environ,check=True)
        replies=[json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(len(replies),2); names={tool["name"] for tool in replies[1]["result"]["tools"]}; self.assertEqual(names,set(module.TOOLS)); self.assertNotIn("secret-capability",completed.stdout)

if __name__=="__main__": unittest.main()
