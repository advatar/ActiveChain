# Read-only MCP interface v1

ActiveChain exposes proof-bearing observations through a host-only Model Context Protocol (MCP)
server. MCP is an interoperability boundary, not an authority boundary: this server cannot sign,
approve, submit, or mutate chain or wallet state.

## Protocol profile

- MCP protocol revision: stable `2025-11-25`.
- Transport: newline-delimited JSON-RPC 2.0 over standard input/output.
- Lifecycle: `initialize`, `notifications/initialized`, then `tools/list` or `tools/call`.
- Bounds: 262,144 bytes per frame, 4,096 unique request IDs per process, four records per page.
- Discovery is deterministic. Every tool is annotated read-only, non-destructive, idempotent, and
  closed-world.
- Tool execution failures are returned as MCP tool results with `isError: true`. JSON-RPC errors are
  reserved for framing, lifecycle, method, and argument faults.

The five v1 tools are `activechain_get_status`, `activechain_list_assets`,
`activechain_verify_record`, `activechain_get_pending_approvals`, and
`activechain_resolve_receipt`. The node-backed adapter cannot expose wallet-local approvals and
returns `unavailable`; a wallet process may supply a separate implementation of the read-only
backend trait.

## Verification boundary

The node adapter obtains data from `DurableRpcStore` and calls the canonical RPC proof verifier
before returning any record. A stale store, malformed envelope, missing record, failed proof, or
unsupported backend fails closed. Responses include canonical record envelopes so a client can
repeat verification independently.

Tool annotations and displayed text are advisory. They never grant capabilities. Future proposing
tools belong to a separate issue and must still pass through canonical native-wallet approval.

## Running

`activechain-mcp` currently starts with an unconfigured backend so integrations can exercise the
protocol safely. Production launch wiring must inject a durable node or wallet backend explicitly;
there is no implicit network endpoint or credential discovery.

The frozen conformance conversation is in
`testing/vectors/mcp-read-only-v1.json`. Unit tests cover lifecycle ordering, request-ID replay,
bounded/malformed frames, deterministic discovery, structured output, unknown tools, excluded
arguments, and fail-closed backend errors.
