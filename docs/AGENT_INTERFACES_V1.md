# MCP and constrained A2UI boundary v1

Status: developmental, planned interoperability boundary; externally unaudited.

This document freezes the first ActiveChain agent-interface contract. MCP is a host transport for
typed tools and proof-bearing resources. A2UI is an optional, bounded presentation proposal for
wallet review and result surfaces. Neither is a principal, capability, approval, signature, receipt,
or consensus input.

## Trust boundary

```text
untrusted AI client
    │ MCP request
    ▼
host-only adapter ── read-only ──► proof-bearing RPC ──► local verifier
    │ proposal
    ▼
canonical intent reconstruction
    │ identity + capability + policy + budget + nonce + expiry
    ▼
native wallet review ◄── constrained A2UI presentation proposal
    │ authenticated approval of the exact commitment
    ▼
signing → ingress → finality → proof-bearing receipt → MCP response
```

The adapter must reconstruct every consequential value from typed inputs. Descriptive model text,
MCP session identity, tool annotations, A2UI labels, and renderer state are non-authoritative. The
wallet displays security-critical values from the reconstructed canonical intent and signs only the
commitment it reviewed.

## Version and encoding

The transport version is `activechain.agent-interfaces.v1`. JSON is UTF-8 and rejects unknown
semantic fields at typed decode boundaries. These JSON DTOs are not canonical ActiveChain
encoding and must never be hashed directly as a protocol intent, capability, action, or receipt.

Maximum frame size is 256 KiB. Arguments and data models are each capped at 64 KiB. Identifiers are
ASCII and at most 128 bytes. A2UI surfaces contain at most 64 components, 32 direct children per
component, and 12 levels of reachable depth. Arbitrary JSON is capped at 16 levels, 256 members per
array/object, and 4 KiB per string.

Machine-readable schemas live under `schema/agent-interfaces/`. Runtime validation remains
mandatory because JSON Schema validation alone does not prove authority, graph integrity, binding
resolution, proof validity, or equality with a canonical intent.

## MCP surface

Revision 1 reserves these exact operations:

| Tool | Class | Authority rule |
| --- | --- | --- |
| `get_status` | read-only | no authority inferred |
| `list_assets` | read-only | no authority inferred |
| `verify_record` | local verification | no authority inferred |
| `get_pending_approvals` | wallet-local read | wallet privacy policy applies |
| `resolve_receipt` | read-only | proof must verify locally |
| `propose_transfer` | consequential proposal | complete authority binding required |
| `submit_anchor_proposal` | consequential proposal | complete authority binding required |

A consequential authority binding names chain, wallet, agent principal, capability, request nonce,
expiry height, and exact canonical intent commitment. Presence of these fields does not prove them;
the gateway must authenticate and verify every value independently. There is deliberately no generic
`sign`, arbitrary RPC passthrough, secret export, direct transfer, or unrestricted submission tool.

## A2UI profile

Revision 1 accepts A2UI protocol version `v0.9` with a restricted catalog: `Button`, `Card`,
`CheckBox`, `Column`, `Divider`, `Icon`, `List`, `Modal`, `RichText`, `Row`, `Table`, and `Text`.
Executable web content, remote media, markdown, video, audio, animation, free-form URLs, and arbitrary
function calls are excluded from approval surfaces.

Bindings are absolute slash paths into the supplied data model. Dot notation, empty path segments,
unresolved component references, duplicate IDs, cycles, and excessive depth fail closed. The only
actions are `activechain.approve`, `activechain.reject`, and `activechain.open_details`; actions are
valid only on `Button` and carry the exact reviewed intent commitment. Renderers must provide a
deterministic native fallback when this profile is invalid or unsupported.

## Error precedence

1. frame size;
2. JSON syntax and typed unknown fields;
3. interface/A2UI version;
4. identifiers and authority shape;
5. argument/data-model bounds;
6. component catalog and graph integrity;
7. bindings;
8. action allowlist and commitment binding.

Errors are structured locally but must not reveal secret state or distinguish whether a guessed
principal, wallet, or capability exists before authentication.

## Threat model

| Threat | Required failure behavior |
| --- | --- |
| Prompt injection requests more authority | capability and policy evaluation ignore prompt claims |
| MCP session impersonates a principal | session identity is never accepted as protocol identity |
| Amount, recipient, asset, or fee substitution | reconstructed commitment differs and approval fails |
| Tool-result or proof substitution | local verifier rejects wrong chain, height, key, or relation |
| Replay after retry/reconnect/restart | durable nonce and request commitment permit one acceptance |
| Capability expiry, revocation, or budget exhaustion | rechecked immediately before signing/submission |
| Misleading A2UI label or hidden control | canonical native values and fallback remain authoritative |
| A2UI action substitution | action name and exact intent commitment fail closed |
| Schema downgrade or unknown fields | exact version/field allowlists reject the payload |
| Deep, cyclic, or oversized input | bounded decoder/graph checks reject before rendering/execution |
| Data exfiltration through UI/media | no remote media, Web component, or arbitrary URL/function call |

## Compatibility

Unknown major interface versions, tools, components, fields, and actions are rejected. Additive work
requires a new declared interface revision when an older implementation cannot preserve identical
security meaning. An MCP or A2UI downgrade can never change the canonical intent version or wallet
approval policy. Logging records request/intent commitments and structured outcomes, never secrets or
raw private arguments.
