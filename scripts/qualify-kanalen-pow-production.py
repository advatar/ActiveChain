#!/usr/bin/env python3
"""Exercise Kanalen's real PoW lifecycle and emit sanitized evidence."""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
import urllib.request

DIGEST = re.compile(r"^[0-9a-f]{96}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
ROOT = Path(__file__).resolve().parents[1]
CHAIN = "b12c1c316717e9669cec36f7632a9080702c57a3125d90c72154f8a7298e4f0b095e6cfe944bd2c9f6535b4c927782f1"
GENESIS = "a836c4d201cda6ba33a01aa48011cf5f4d6acdfd1ec409d322dc1b56ed3552a25dcb158e0b1ec0352728653d315d477c"
REMOTE_ROOT = "/Users/johansellstrom/activechain-deploy/kanalen"


def run(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, **options)


def ssh(host: str, command: str, capture: bool = True) -> str:
    completed = run(
        ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", host, command],
        capture_output=capture,
    )
    return completed.stdout.strip() if capture else ""


def scp(source: Path, host: str, destination: str) -> None:
    run(
        [
            "scp",
            "-q",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            str(source),
            f"{host}:{destination}",
        ]
    )


def remote_json(host: str, helper: str, command: str, artifact: str, request_id: str) -> dict:
    output = ssh(
        host,
        " ".join(shlex.quote(value) for value in ["python3", helper, command, artifact, request_id]),
    )
    value = json.loads(output)
    if not isinstance(value, dict):
        raise RuntimeError(f"{command} returned malformed JSON")
    return value


def require_identity(value: dict) -> None:
    if value.get("chain_id") != CHAIN or value.get("genesis_commitment") != GENESIS:
        raise RuntimeError("deployed lifecycle returned the wrong network identity")


def tool(directory: Path, name: str) -> Path:
    path = directory / name
    if not os.access(path, os.X_OK):
        raise RuntimeError(f"required release tool is unavailable: {path}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="johansellstrom@192.168.2.126")
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-tools", type=Path, default=ROOT / "target/release")
    arguments = parser.parse_args()
    if not REVISION.fullmatch(arguments.expected_revision):
        raise SystemExit("expected revision must be a full lowercase Git commit")
    if arguments.output.exists():
        raise SystemExit("refusing to overwrite production qualification evidence")

    tools = arguments.release_tools
    source_tool = tool(tools, "actum-work-qualification-source")
    prover = tool(tools, "actum-work-prover")
    keygen = tool(tools, "actum-trust-keygen")
    signer_set_tool = tool(tools, "actum-trust-signer-set")
    bundle_tool = tool(tools, "actum-trust-bundle")
    r0vm = Path(shutil.which("r0vm") or "")
    if not r0vm.is_absolute() or not os.access(r0vm, os.X_OK):
        raise SystemExit("r0vm is unavailable")

    active = ssh(arguments.host, f"basename $(readlink {shlex.quote(REMOTE_ROOT + '/current')})")
    if active != arguments.expected_revision:
        raise RuntimeError(f"deployed revision is {active}, expected {arguments.expected_revision}")
    run_id = f"pow-{int(time.time())}-{secrets.token_hex(4)}"
    remote_dir = f"{REMOTE_ROOT}/work-proof-qualification/{run_id}"
    remote_current = f"{REMOTE_ROOT}/current"
    helper = f"{remote_current}/scripts/qualification-http.py"
    ssh(arguments.host, f"install -d -m 0700 {shlex.quote(remote_dir)}")

    cases: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="activechain-pow-production-") as temporary:
        private = Path(temporary)
        private.chmod(0o700)
        project_id = secrets.token_hex(48)
        usage_domain = secrets.token_hex(48)
        claimant_secret = secrets.token_hex(48)
        now_ms = int(time.time()) * 1000
        source = private / "source.json"
        policy = private / "policy.hex"
        run([str(source_tool), str(source), str(policy), project_id, str(now_ms)], capture_output=True)
        secret_file = private / "claimant-secret.hex"
        secret_file.write_text(claimant_secret + "\n")
        secret_file.chmod(0o600)
        output_directory = private / "proofs"
        output_directory.mkdir(mode=0o700)
        socket = private / "prover.sock"
        config = private / "config.json"
        config.write_text(
            json.dumps(
                {
                    "schema": "actum.work-prover.config.v1",
                    "chain_id": CHAIN,
                    "genesis_commitment": GENESIS,
                    "usage_domain": usage_domain,
                    "submitter_id": "a1" * 48,
                    "policy_envelope_hex": policy.read_text().strip(),
                    "claimant_secret_file": str(secret_file),
                    "output_directory": str(output_directory),
                    "socket_path": str(socket),
                    "r0vm_path": str(r0vm),
                },
                sort_keys=True,
            )
            + "\n"
        )
        config.chmod(0o600)
        sidecar = subprocess.Popen(
            [str(prover), "--serve", str(config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            for _ in range(100):
                if socket.exists():
                    break
                if sidecar.poll() is not None:
                    raise RuntimeError("work prover sidecar exited before becoming ready")
                time.sleep(0.1)
            environment = os.environ.copy()
            environment["ACTUM_WORK_PROVER_SOCKET"] = str(socket)
            proof_result = json.loads(
                run(
                    [str(prover), "--input", str(source), "--request-id", run_id],
                    env=environment,
                    capture_output=True,
                    timeout=900,
                ).stdout
            )
        finally:
            sidecar.terminate()
            try:
                sidecar.wait(timeout=10)
            except subprocess.TimeoutExpired:
                sidecar.kill()
                sidecar.wait()
        if proof_result.get("status") != "proof_generated":
            raise RuntimeError("real RISC Zero proof generation failed")
        artifact = Path(proof_result["artifact_path"])
        claim_id = proof_result["claim_id"]
        if not DIGEST.fullmatch(claim_id) or proof_result.get("project_id") != project_id:
            raise RuntimeError("prover returned malformed claim bindings")
        remote_artifact = f"{remote_dir}/admission.json"
        scp(artifact, arguments.host, remote_artifact)
        ssh(arguments.host, f"chmod 0600 {shlex.quote(remote_artifact)}")

        delivery_id = f"{run_id}-delivery"
        delivered = remote_json(arguments.host, helper, "delivery", remote_artifact, delivery_id)
        require_identity(delivered)
        if delivered.get("status") != "delivered" or delivered.get("duplicate") is not False:
            raise RuntimeError("first durable delivery was not accepted exactly once")
        duplicate_delivery = remote_json(
            arguments.host, helper, "delivery", remote_artifact, delivery_id
        )
        if duplicate_delivery.get("status") != "delivered" or duplicate_delivery.get("duplicate") is not True:
            raise RuntimeError("durable delivery retry was not idempotent")
        cases.append({"id": "real_delivery_webhook", "result": "passed", "reference": delivered["reference"]})

        anchor = remote_json(arguments.host, helper, "anchor", remote_artifact, run_id)
        require_identity(anchor)
        if anchor.get("status") not in {"submitted", "pending"}:
            raise RuntimeError("native anchor was not submitted")
        ssh(arguments.host, f"bash {shlex.quote(remote_current + '/scripts/run-kanalen-round.sh')}", capture=False)
        for _ in range(30):
            anchor = remote_json(arguments.host, helper, "anchor", remote_artifact, run_id)
            if anchor.get("status") == "finalized":
                break
            if anchor.get("status") not in {"submitted", "pending"}:
                raise RuntimeError("native anchor entered a terminal failure")
            time.sleep(1)
        if anchor.get("status") != "finalized" or not DIGEST.fullmatch(anchor.get("reference", "")):
            raise RuntimeError("native anchor did not finalize")

        remote_anchor = f"{remote_dir}/anchor-request.bin"
        ssh(
            arguments.host,
            " ".join(
                shlex.quote(value)
                for value in ["python3", helper, "extract-anchor", remote_artifact, remote_anchor]
            ),
        )
        lag_probe = subprocess.run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                arguments.host,
                " ".join(
                    shlex.quote(value)
                    for value in [
                        f"{remote_current}/bin/actum-anchor-evidence",
                        "127.0.0.1:49151",
                        remote_anchor,
                        f"{REMOTE_ROOT}/work-proof/trust.bin",
                        f"{remote_dir}/lag-evidence.bin",
                    ]
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        lag_output = lag_probe.stdout + lag_probe.stderr
        if lag_probe.returncode == 0 or "re-issue the bundle at the served checkpoint" not in lag_output:
            raise RuntimeError("the pre-advance trust checkpoint did not prove checkpoint lag")

        finality = private / "finality.bundle"
        execution = private / "execution.snapshot"
        run(["scp", "-q", f"{arguments.host}:{REMOTE_ROOT}/chain/finality.bundle", str(finality)])
        run(["scp", "-q", f"{arguments.host}:{REMOTE_ROOT}/chain/execution.snapshot", str(execution)])
        proof_binding = private / "proof.json"
        proof_binding.write_text(
            ssh(arguments.host, f"{shlex.quote(remote_current + '/bin/actum-work-proof-trust-bootstrap')} --emit-trust-inputs")
            + "\n"
        )
        seed = private / "root.seed"
        public = private / "root.pub"
        run([str(keygen), str(seed), str(public)], capture_output=True)
        signers = private / "signers.json"
        signers.write_text(
            json.dumps(
                [
                    {
                        "public_key_hex": public.read_text().strip(),
                        "valid_from_sequence": 1,
                        "valid_until_sequence": 64,
                    }
                ]
            )
            + "\n"
        )
        signer_set = private / "trust-signer-set.bin"
        run([str(signer_set_tool), str(signer_set), "1", "1", str(signers)], capture_output=True)
        policy_id = run([str(source_tool), "--policy-id"], capture_output=True).stdout.strip()
        issued = int(time.time()) * 1000
        spec = private / "spec.json"
        spec.write_text(
            json.dumps(
                {
                    "bundle_sequence": 1,
                    "policy_id_hex": policy_id,
                    "policy_revision": 1,
                    "issued_at_ms": issued,
                    "not_before_ms": issued,
                    "not_after_ms": issued + 3650 * 86_400_000,
                },
                sort_keys=True,
            )
            + "\n"
        )
        body = private / "body.bin"
        signature = private / "root.sig.json"
        signed = private / "signed-trust-bundle.bin"
        run(
            [
                str(bundle_tool),
                "prepare",
                str(body),
                str(spec),
                str(proof_binding),
                str(finality),
                str(execution),
                str(signer_set),
            ],
            capture_output=True,
        )
        run([str(bundle_tool), "sign", str(signature), str(seed), str(body)], capture_output=True)
        run(
            [
                str(bundle_tool),
                "assemble",
                str(signed),
                str(body),
                str(signer_set),
                str(issued),
                str(signature),
            ],
            capture_output=True,
        )
        signed.chmod(0o600)
        signer_set.chmod(0o600)
        remote_signed = f"{remote_dir}/signed-trust-bundle.bin"
        remote_set = f"{remote_dir}/trust-signer-set.bin"
        scp(signed, arguments.host, remote_signed)
        scp(signer_set, arguments.host, remote_set)
        ssh(
            arguments.host,
            f"chmod 0600 {shlex.quote(remote_signed)} {shlex.quote(remote_set)} && "
            f"bash {shlex.quote(remote_current + '/scripts/rebootstrap-testnet-work-proof-trust.sh')} "
            f"{shlex.quote(remote_signed)} {shlex.quote(remote_set)} {arguments.expected_revision}",
            capture=False,
        )
        seed.unlink()

        remote_evidence = f"{remote_dir}/checkpoint-evidence.bin"
        ssh(
            arguments.host,
            " ".join(
                shlex.quote(value)
                for value in [
                    f"{remote_current}/bin/actum-anchor-evidence",
                    "127.0.0.1:49151",
                    remote_anchor,
                    f"{REMOTE_ROOT}/work-proof/trust.bin",
                    remote_evidence,
                ]
            ),
        )
        checkpoint_evidence = private / "checkpoint-evidence.bin"
        run(["scp", "-q", f"{arguments.host}:{remote_evidence}", str(checkpoint_evidence)])
        admission = json.loads(artifact.read_text())
        admission["checkpointed_anchor_evidence_envelope_hex"] = checkpoint_evidence.read_bytes().hex()
        artifact.write_text(json.dumps(admission, separators=(",", ":"), sort_keys=True) + "\n")
        artifact.chmod(0o600)
        scp(artifact, arguments.host, remote_artifact)
        ssh(arguments.host, f"chmod 0600 {shlex.quote(remote_artifact)}")

        verified = remote_json(arguments.host, helper, "verify", remote_artifact, run_id)
        result = verified.get("result") if verified.get("schema") == "actum.work-proof.admit.result.v1" else None
        if not isinstance(result, dict) or result.get("claim_id") != claim_id:
            raise RuntimeError("stateful verifier did not accept the exact claim")
        if not all(result.get(field) is True for field in ("relation_verified", "anchor_verified", "usage_verified")):
            raise RuntimeError("stateful verifier did not prove every verification dimension")
        if result.get("idempotent") is not False:
            raise RuntimeError("first stateful admission was unexpectedly idempotent")
        replay = remote_json(arguments.host, helper, "verify", remote_artifact, run_id)
        if replay.get("result", {}).get("idempotent") is not True:
            raise RuntimeError("exact stateful replay was not idempotent")
        uid = ssh(arguments.host, "id -u")
        label = "dev.activechain.kanalen.work-proof"
        ssh(
            arguments.host,
            f"launchctl bootout gui/{uid}/{label} >/dev/null 2>&1 || true; sleep 1; "
            f"launchctl bootstrap gui/{uid} {shlex.quote(remote_current + '/launchagents/' + label + '.plist')}",
        )
        for _ in range(30):
            try:
                restarted = remote_json(arguments.host, helper, "verify", remote_artifact, run_id)
                if restarted.get("result", {}).get("idempotent") is True:
                    break
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                pass
            time.sleep(1)
        else:
            raise RuntimeError("durable admission did not survive verifier restart")

        with urllib.request.urlopen(
            "https://delivery.kanalen.actum.network/v1/health", timeout=15
        ) as response:
            delivery_health = json.load(response)
        if delivery_health.get("deployment_revision") != arguments.expected_revision:
            raise RuntimeError("public delivery TLS origin serves the wrong revision")
        cases.extend(
            [
                {"id": "real_finalized_anchor", "result": "passed", "reference": anchor["reference"]},
                {"id": "real_checkpoint_lag_and_advance", "result": "passed"},
                {"id": "real_stateful_verification", "result": "passed", "claim_id": claim_id},
                {"id": "restart_replay_privacy", "result": "passed"},
            ]
        )
        evidence = {
            "$schema": "https://actum.network/evidence/pow-production-qualification/v1",
            "activechain_revision": arguments.expected_revision,
            "chain_id": CHAIN,
            "genesis_commitment": GENESIS,
            "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "production_qualified": True,
            "project_id": project_id,
            "policy_id": policy_id,
            "policy_revision": 1,
            "cases": cases,
            "privacy": {
                "raw_telemetry_published": False,
                "bearer_material_published": False,
                "claimant_secret_published": False,
                "ephemeral_trust_seed_destroyed": True,
            },
        }
        arguments.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    ssh(arguments.host, f"rm -rf {shlex.quote(remote_dir)}")
    print(f"Kanalen PoW production qualification passed for {arguments.expected_revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
