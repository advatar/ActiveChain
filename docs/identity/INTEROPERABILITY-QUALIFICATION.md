# Identity interoperability qualification

Status: implementation/vector qualified; physical-device and independent-review gates remain open.

| Profile or property | Implemented | Automated vectors | Physical Apple | Physical Android | Independent review |
|---|---:|---:|---:|---:|---:|
| VCIssuer SD-JWT VC → EUWallet → ActiveChain | yes | yes | blocked by #580 | blocked by #578 | blocked by #579 |
| VCIssuer mdoc → EUWallet → ActiveChain | yes | yes | blocked by #580 | blocked by #578 | blocked by #579 |
| OpenID4VP pinned transport | yes | yes | simulator unit-tested | unit-tested, no device | blocked by #579 |
| Custody, recovery, deletion, rotation/revocation | implemented boundaries | synthetic cases | blocked by #580 | blocked by #578 | blocked by #579 |
| Offline receipt reproduction | yes | yes | blocked by #580 | blocked by #578 | blocked by #579 |

The three repositories share byte-identical bridge files and pinned SHA-256 digests. Reproduce the
implemented boundary check with:

```sh
python3 scripts/check-cross-device-identity-qualification.py \
  --vcissuer ../VCIssuer --euwallet ../EUWallet --vectors-only
```

Removing `--vectors-only` requires a machine-readable evidence file containing physical Apple and
Android device/OS identities, every required adversarial outcome, and an independent review artifact
with no unresolved blocking findings. Simulator tests, self-review, or an empty device matrix cannot
produce a passing qualification result.

No current evidence supports a claim of EUDI certification, independent audit, production hardware
interoperability, or general OpenID4VC conformance beyond the pinned SD-JWT VC/mdoc profiles.
