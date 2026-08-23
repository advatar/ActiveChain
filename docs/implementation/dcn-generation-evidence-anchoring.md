# DCN verified-generation evidence anchoring

Issue [#826](https://github.com/advatar/ActiveChain/issues/826) qualifies the narrow Actum boundary used by DCN G8. Actum does not verify Gemma or Atlas proofs. DCN first finalizes a `dcn.generation-attestation.v1` object as `VERIFIED`; Actum then anchors a privacy-safe canonical commitment through the existing `DigestAnchorStatementV1` state and consensus path.

## Native boundary

The authorized application domain is:

```text
dcn.generation-attestation.evidence-anchor.v1
```

`actum-anchor-submit` accepts a versioned evidence request only when the configured operator domain matches that value exactly. It converts the 32-byte evidence commitment into the existing canonical digest-anchor statement. The validator-owned anchor action, fee path, consensus, finality evidence, durable registry, sparse-state proof, and query path are unchanged.

The submission request contains only:

- a commitment-derived evidence identifier;
- the canonical `sha256:` EvidenceAnchor commitment;
- the exact application domain.

It does not contain prompts, responses, K/V state, proof bytes, tenant identifiers, audience identifiers, credentials, or artifact locations. Actum validates canonical commitment syntax, configured application-domain authorization, native action authorization, replay/idempotency, consensus, finality, and finalized state inclusion. DCN remains responsible for Atlas proof validity, token-policy validity, state-chain validity, identity consistency, bundle integrity, and the `VERIFIED` publication gate.

## Finality and retrieval

The qualification fixture uses three real local validators. It submits the same evidence before and after an RPC restart, obtains one deterministic statement reference, includes the operator-owned action in consensus, reconciles the finalized anchor registry, and exports:

- the finalized native record;
- its sparse-state inclusion proof;
- checkpoint finality evidence;
- the canonical native finality envelope consumed by DCN's independent verifier.

The qualified fixture finalized at height 2 with one anchored state object. Exact measurements and identities are recorded in DCN's private `gemma-g8/qualification-report.json`.

## Run the fixture

The standalone Actum path accepts any canonical test commitment:

```sh
output=$(mktemp -d /tmp/actum-dcn-evidence.XXXXXX)
rm -r "$output"
RUSTUP_TOOLCHAIN=1.97.1 \
  scripts/qualify-dcn-evidence-anchor.sh \
  sha256:$(printf '11%.0s' {1..32}) \
  sha256:$(printf '22%.0s' {1..32}) \
  "$output"
```

For cross-repository qualification, set the documented `DCN_G8_*` variables to the DCN anchor tool, qualified attestation/context, durable store, and attestation ID. The fixture then stages the exact Actum statement in DCN and independently validates the exported native finality envelope before recording `NETWORK_FINALIZED`.

This milestone qualifies evidence anchoring only. It does not qualify Atlas verification by validators, payment settlement, recursive aggregation, public-chain immutability beyond the exercised Actum finality model, or economic rewards.
