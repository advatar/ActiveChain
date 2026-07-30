# Agent interface qualification v1

Status: developmental and externally unaudited. Passing this qualification demonstrates the stated
fail-closed engineering invariants; it is not an external security assessment or production-readiness
claim.

Run the bounded normal-test qualification from the repository root:

```sh
scripts/qualify-agent-interfaces.sh
```

The suite exercises the typed interface bounds, MCP lifecycle and schema enforcement, durable
proposal replay and substitution defenses, canonical native-wallet review/sign/submit boundary,
constrained A2UI validation and action binding, and the three-validator receipt rehearsal. Frozen
MCP and A2UI vectors are checked for drift. The repository's exhaustive deterministic-kernel gate is
outside this command and is intentionally not implied by a passing result.

## Compatibility matrix

| Boundary | Supported version | Other versions | Compatibility rule |
| --- | --- | --- | --- |
| ActiveChain agent DTOs | `activechain.agent-interfaces.v1` | rejected | exact revision and typed fields |
| MCP transport | `2025-11-25` | rejected before tools are listed | no negotiation or downgrade |
| Constrained A2UI | `v0.9` | native fallback only | unsupported surfaces never authorize |
| Canonical action intent | schema 1, type `0x0149` | rejected | canonical decode and commitment required |
| Authorized action intent | schema 1, type `0x014b` | rejected | exact reviewed commitment and valid signature |

Patch-level client changes are compatible only when they emit the exact supported wire revision and
preserve all declared bounds. New tools, fields, components, actions, or altered security meaning
require a new declared revision. Unknown or missing versions, schema downgrade, and capability
claims inferred from MCP session data fail closed. A2UI incompatibility selects the deterministic
native display; it never weakens wallet policy.

## Qualified adversarial classes

- Prompt text and tool metadata cannot create a principal, capability, budget, signature, or receipt.
- Unknown tools/arguments, result substitution, wrong proof relationships, and version downgrade are
  rejected before authority is exercised.
- Amount, asset, fee, recipient, chain, wallet, capability, nonce, expiry, and commitment changes
  alter or invalidate the canonical intent.
- Duplicate delivery, reconnect, restart, conflicting retry, nonce replay, stale revision, expiry,
  and budget exhaustion are covered by durable gateway and wallet lifecycle tests.
- Control characters, bidi overrides, deceptive prose, unsupported actions/components, unresolved
  bindings, cycles, excessive depth, oversized frames/models, and malformed JSON fail closed.
- Fixed input, graph, request-count, component, identifier, and snapshot bounds constrain memory and
  work before canonical reconstruction. Host process deadlines and connection limits remain an
  operator responsibility because the MCP core deliberately has no networking runtime.

## Audit and privacy records

Audit events record request ID, proposal ID, canonical intent commitment, outcome class, lifecycle
revision, transaction ID, finalized height, and receipt commitment where applicable. Do not log raw
proposal arguments, agent prose, canonical envelopes, public-key callback contexts, credentials,
private keys, signatures beyond a commitment, or pending-approval contents. Logs must be access
controlled, retention bounded, and commitment-addressable for incident correlation.

### Privacy and telemetry

The default local adapter emits no network telemetry. Operators may collect aggregate counts and
latency/error classes without wallet IDs, principals, recipients, assets, amounts, request text, or
proof payloads. Pending approvals are wallet-local. Any remote telemetry, crash upload, or support
bundle is a separate data-egress feature requiring explicit policy review and opt-in.

## Incident disable procedure

1. Stop the MCP host adapter or remove its local socket/stdio launch registration. This disables new
   observations and proposals without changing consensus state.
2. Disable proposal tools at the host routing layer while retaining independently verified read-only
   RPC only if incident policy permits it. Never replace a disabled proposal with direct submission.
3. Revoke the affected agent capability on chain and wait for finalized revocation before treating it
   as effective. Native wallets must continue rechecking revocation, expiry, budget, and commitment.
4. Preserve bounded commitment-only audit records and proposal/wallet snapshots; restrict access and
   do not publish raw arguments or secrets.
5. Reconcile pending/submitted proposals against finalized receipts. Mark indeterminate operations
   failed locally only after proof-bearing resolution; never infer failure solely from timeout.
6. Restore service only with the exact supported versions, green qualification suite, reconciled
   lifecycle state, and documented incident owner approval.

Slow clients and backends must be isolated by the embedding host with per-connection deadlines,
bounded concurrent sessions, and admission rate limits. Terminating a slow session is safe because
durable request IDs and nonces make retries idempotent; the host must not invent a successful result.

## External audit scope

The next independent review must cover the MCP frame/session parser and schemas; authenticated
proposal gateway and durable replay journal; canonical intent/authorization codecs; native wallet C,
Android, and Apple review/sign/submit custody paths; A2UI validator, renderer, native fallback, and
action dispatcher; RPC/finality/application-receipt verification; snapshot durability and corruption
handling; host deadline/rate-limit/logging configuration; and this qualification suite's attack
coverage. The audit should include confused-deputy, prompt injection, substitution, race/restart,
Unicode deception, parser/resource exhaustion, privacy egress, and incident-disable exercises.
