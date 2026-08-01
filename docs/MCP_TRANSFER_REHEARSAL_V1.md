# MCP Transfer Rehearsal V1

This developmental, unaudited rehearsal exercises the complete bounded MCP transfer path against
a deterministic local three-validator finality certificate. It is an engineering acceptance tool,
not a security audit or a production deployment guide.

Run it from the repository root:

```sh
scripts/rehearse-mcp-transfer.sh
```

The script creates a disposable directory, runs the normal affected Rust binary, validates its JSON
report, and removes all snapshots on exit. The report correlates the MCP request, proposal, canonical
intent, wallet authorization, submitted transaction, finalized height, and application receipt. It
also exercises reconnect/retry idempotence and the pending, denied, expired, submitted, finalized,
and failed outcomes.

## Trust boundaries

- MCP and A2UI are proposal and presentation surfaces only. They cannot sign, submit, finalize, or
  manufacture a verified receipt.
- The proposal gateway admits a canonical `ActionIntentV1` under the authenticated capability and
  durable replay journal. Repeated request IDs return the original result without creating a second
  intent.
- The wallet reconstructs review facts from canonical bytes, compares the exact reviewed
  commitment, checks expiry, invokes caller-owned signing custody, verifies the resulting signature,
  and only then forwards the authorized envelope.
- Validator signatures and the quorum certificate establish finality. The rehearsal uses three
  deterministic local validator keys and does not persist those keys or model production custody.
- Receipt verification is independent of MCP: the RPC verifier checks the chain genesis, finality
  bundle, ordered action-set proof, and canonical application receipt before MCP presents the result.
- All generated state is test-only and disposable. No wallet secret, validator secret, callback
  context, or private key is written to the proposal, wallet, or RPC snapshots.

Success means the integration boundaries agree on the same commitments and denial rules. It does
not establish production security, networking resilience, side-channel resistance, or audited key
custody.
