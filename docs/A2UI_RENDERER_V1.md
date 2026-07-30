# Constrained A2UI renderer v1

The renderer is a host-only presentation adapter. It receives a typed
`TransferApprovalFacts` value reconstructed by the native wallet and emits both a constrained A2UI
surface and a deterministic native fallback. It does not parse an agent-authored transfer into
security-critical facts.

## Security boundary

- Amount, asset, recipient, network, fee, expiry, and intent commitment come only from the native
  wallet DTO.
- Agent prose is rendered in a separate section labeled unverified. Control characters, bidi
  overrides/isolates, zero-width controls, and oversized values are rejected.
- Approve, reject, and details actions use wallet-owned labels and are bound to the exact 384-bit
  intent commitment. Dispatch only produces a `WalletApprovalCommand`; it cannot sign or submit.
- Every generated surface passes the allowlist, graph, binding, action, payload, and version checks
  in `activechain-agent-interfaces`. If validation fails, the A2UI surface is omitted and the native
  fallback remains available.
- The profile contains no `Web`, remote media, executable content, hidden controls, or generated
  action labels.

The first supported surface is transfer review. Capability, enrollment, credential disclosure,
proof status, receipt, and authenticated native-wallet dispatch remain gated on their owning DTO
and wallet-integration issues rather than accepting placeholder authority.

## Accessibility profile

The conformance fixture uses one card shell, three compact semantic sections, 24–40px scale-aware
text tiers, high-contrast warnings, and vertically isolated actions. Canonical values are not
silently truncated. The agent explanation may be clamped because it is explicitly secondary and
untrusted. Actions use visible text and content-driven sizing.

Fixtures are ordered as required by the A2UI update stream:

1. `testing/vectors/a2ui-transfer-review-components.json`
2. `testing/vectors/a2ui-transfer-review-datamodel.json`

Both share `surfaceId: activechain.transfer_review.v1` and pass the repository's A2UI validation
profile.
