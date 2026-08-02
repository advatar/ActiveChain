#!/usr/bin/env python3
"""Cross-repository identity vectors and physical-device qualification evidence gate."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

REQUIRED_CASES = {"locked-device","biometric-cancel","biometric-lockout","restart","recovery-migration","key-rotation","revocation","deletion","stale-trust-status","wrong-issuer-schema-holder","wrong-audience-action-network","replay","duplicate-callback","transport-cancellation","malformed-sd-jwt","malformed-mdoc","over-disclosure","offline-verification"}
FORBIDDEN = ("raw_credential", "date_of_birth", "account_identifier", "tls_transcript")

def digest(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def load_manifest(repo: Path) -> dict: return json.loads((repo / "testing/vectors/identity-bridge-manifest-v1.json").read_text())
def vector_map(repo: Path, manifest: dict) -> dict[str,str]:
    values={}
    for item in manifest["files"]:
        path=repo/"testing/vectors"/item["path"]
        if digest(path)!=item["sha256"]: raise SystemExit(f"digest mismatch: {path}")
        values[item["path"]]=item["sha256"]
        text=path.read_text(errors="strict").lower()
        if any(secret in text for secret in FORBIDDEN): raise SystemExit(f"private field in shared vector: {path}")
    return values
def validate_evidence(path: Path) -> None:
    evidence=json.loads(path.read_text()); platforms={entry["platform"]:entry for entry in evidence["devices"]}
    if set(platforms)!={"apple","android"}: raise SystemExit("physical Apple and Android evidence required")
    for name,entry in platforms.items():
        if entry.get("physical") is not True or not entry.get("device") or not entry.get("os"): raise SystemExit(f"invalid {name} device evidence")
        outcomes={case["case"]:case["outcome"] for case in entry.get("cases",[])}
        if REQUIRED_CASES-set(outcomes) or any(outcomes[c]!="pass" for c in REQUIRED_CASES): raise SystemExit(f"incomplete {name} cases")
    review=evidence.get("independent_review",{})
    if not review.get("reviewer") or not review.get("artifact_sha256") or review.get("open_blocking_findings")!=0: raise SystemExit("independent review unresolved")

def main() -> None:
    p=argparse.ArgumentParser();p.add_argument("--activechain",type=Path,default=Path.cwd());p.add_argument("--vcissuer",type=Path,required=True);p.add_argument("--euwallet",type=Path,required=True);p.add_argument("--evidence",type=Path);p.add_argument("--vectors-only",action="store_true");a=p.parse_args()
    repos=[a.activechain.resolve(),a.vcissuer.resolve(),a.euwallet.resolve()]
    manifests=[load_manifest(repo) for repo in repos]; maps=[vector_map(repo,m) for repo,m in zip(repos,manifests)]
    if not (maps[0]==maps[1]==maps[2]): raise SystemExit("cross-repository vector manifests differ")
    if not a.vectors_only:
        if a.evidence is None: raise SystemExit("physical-device/review evidence required")
        validate_evidence(a.evidence)
    print(f"identity qualification vectors verified: {len(maps[0])} byte-identical files across 3 repositories")

if __name__=="__main__": main()
