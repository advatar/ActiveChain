# `pow.actum.network` end-to-end qualification v1

#778 uses two evidence tiers. Neither tier can substitute for the other.

## Deterministic exact-revision evidence

The split deterministic-kernel runtime job runs:

```sh
python3 scripts/qualify-pow-e2e.py \
  --revision "$GITHUB_SHA" \
  --output "pow-e2e-deterministic-${GITHUB_SHA}.json"
```

The resulting artifact covers bounded plugin transport, outage and malformed-response handling,
idempotent delayed recovery, delivery/anchor separation, pending/finalized separation, durable
restart and replay behavior, concurrent nullifier admission, privacy, the real RISC Zero verifier
tests, and the frozen ProofOfWork JSON subprocess contract.

The artifact intentionally sets `production_qualified` to `false`. A green deterministic gate does
not prove that a public endpoint is deployed, authenticated, connected to the intended network, or
running the qualified revision.

## Mandatory production evidence

Promotion requires a second sanitized artifact from the exact deployed revisions. It must contain:

- ActiveChain and ProofOfWork commit IDs and deployment bundle digests;
- the public origins exercised and their pinned chain/genesis identifiers, without credentials;
- an idempotent real `ACTUM_DELIVERY_WEBHOOK` delivery and delayed-recovery result;
- an authenticated real `ACTUM_ANCHOR_URL` submission resolved to exact finalized state;
- the native telemetry-anchor action, matching block receipt, finality evidence, and exact
  operator-selected trusted checkpoint;
- one accepted stateful claim with `relation_verified`, `anchor_verified`, and `usage_verified`;
- an exact retry marked idempotent and a different-claim nullifier replay rejected atomically;
- restart rehearsals for plugin lifecycle, trust state, usage state, and the deployed application;
- privacy inspection showing no bearer, capability, raw telemetry, prompt, source, or receipt bytes;
- landing-page and explorer screenshots or machine assertions matching the deployed compatibility
  matrix.

The production artifact must fail closed when any endpoint, trust bundle, proof image, state proof,
or deployment revision is absent or mismatched. Secrets, raw artifacts, and subprocess stderr are
never evidence fields.

## Promotion rule

Keep every affected control labelled **Preview** until both artifacts pass for the exact deployed
revisions. Delivery never implies anchoring. Finalized transport status never substitutes for
native action/receipt/finality verification. Relation verification never implies nullifier admission. Only all
three verified dimensions may render a verified work claim.
