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

### Fixture independence

Trust fixtures are constructed independently of the evidence they authorize. A test must never
assign an operator-held trust field from the artifact under verification. Deriving
`checkpoint_height`, `checkpoint_block_id`, `checkpoint_state_root`,
`checkpoint_finality_commitment`, or `validator_set_root` from the anchor evidence makes the test
pass under any binding rule, including an incorrect one, and previously masked a checkpoint binding
that admitted only anchors landing in the exact pinned block.

Where a fixture helper still derives checkpoint identity for convenience, the binding must
additionally be pinned by dedicated cases that vary one side only: an anchor finalized strictly
below the checkpoint is accepted, a substituted checkpoint identity is rejected as terminal, and an
anchor finalized above the checkpoint is rejected as retryable `CheckpointLag`.

## Mandatory production evidence

Promotion requires a second sanitized artifact from the exact deployed revisions. It must contain:

- ActiveChain and ProofOfWork commit IDs and deployment bundle digests;
- the public origins exercised and their pinned chain/genesis identifiers, without credentials;
- an idempotent real `ACTUM_DELIVERY_WEBHOOK` delivery and delayed-recovery result;
- an authenticated real `ACTUM_ANCHOR_URL` submission resolved to exact finalized state;
- the native telemetry-anchor action, matching block receipt, finality evidence, and exact
  operator-selected trusted checkpoint;
- one accepted stateful claim with `relation_verified`, `anchor_verified`, and `usage_verified`;
- an anchor finalized above the operator-selected checkpoint rejected as retryable `CheckpointLag`,
  then accepted unchanged after the operator advances the checkpoint bundle;
- an exact retry marked idempotent and a different-claim nullifier replay rejected atomically;
- restart rehearsals for plugin lifecycle, trust state, usage state, and the deployed application;
- privacy inspection showing no bearer, capability, raw telemetry, prompt, source, or receipt bytes;
- landing-page and explorer screenshots or machine assertions matching the deployed compatibility
  matrix.

The production artifact must fail closed when any endpoint, trust bundle, proof image, state proof,
or deployment revision is absent or mismatched. Secrets, raw artifacts, and subprocess stderr are
never evidence fields.

The production runner also executes the checked-out ProofOfWork adapter against the same admission
artifact and protected deployed verifier. Its temporary token copy is mode 0600, deleted before
evidence is written, and only the exact ProofOfWork commit and pass/fail result cross that boundary.

Before the state-changing lifecycle, run the no-build deployment preflight workflow. It checks the
active release symlink and archive digest, immutable chain/genesis identity, private credential-file
permissions, authenticated local anchor/verifier health, unauthorized rejection, and each public
TLS origin. It deliberately reports `production_qualified: false`; passing preflight proves that the
exact deployment is reachable and ready to attempt lifecycle qualification, not that the lifecycle
has passed.

The canonical delivery origin is `https://delivery.kanalen.actum.network`. The former
`delivery.kanalen.activechain.dev` SNI remains a temporary gateway alias but is not a qualification
dependency and may have no DNS record.

## Promotion rule

Keep every affected control labelled **Preview** until both artifacts pass for the exact deployed
revisions. Delivery never implies anchoring. Finalized transport status never substitutes for
native action/receipt/finality verification. Relation verification never implies nullifier admission. Only all
three verified dimensions may render a verified work claim.
