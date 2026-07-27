# Compute-job boundary v1

Compute jobs are application objects, not consensus-special instructions. A job manifest commits
to code, inputs, resource limits, policy, agent authority, and required evidence. Validators only
consensus-validate the canonical object/action, authorization, fee, and receipt bindings.

## Execution evidence

An execution provider emits a commitment-only evidence record containing the job ID, input/output
commitments, execution environment revision, resource counters, result status, and evidence hash.
Raw files and private inputs remain off-chain. A receipt binds the evidence to the finalized action
and exact policy revision.

## Dispute and failure

- Invalid manifests or unauthorized providers are rejected before execution.
- Missing evidence is `pending`, never success.
- Conflicting evidence is a one-shot dispute and cannot mutate the original job.
- A finalized failure receipt is distinct from an absent receipt and is auditable offline.
- Slashing, refunds, and rewards follow the application policy; they do not change consensus rules.

Future proof-carrying execution may add a reserved evidence kind, but v1 clients reject unknown
proof kinds and do not infer success from an unrecognized record.
