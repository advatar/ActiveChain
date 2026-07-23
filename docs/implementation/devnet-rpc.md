# Development-network RPC contract

RPC schema revision 1 is a bounded canonical protocol shared by servers, clients, and future light
clients. `activechain-rpc-types` is `no_std` and freezes:

- chain identity, immutable genesis commitment, protocol and RPC schema revisions;
- finalized height and deterministic healthy/stale state derived from explicit timestamps;
- an ordered supported-proof registry;
- typed status, keyed query, and cursor-paginated request variants;
- proof-bearing state, action, and receipt records; and
- typed not-found, stale, unsupported-proof, invalid-request, deadline, and internal failures.

`activechain-rpc-server` persists the complete ordered finalized query index using canonical
encoding, a domain-separated corruption tag, temporary-file publication, `fsync`, rename, and
directory `fsync`. Replacement rejects chain/genesis changes and finalized-height regression.

The network boundary uses a four-byte big-endian frame length, a 4 MiB hard limit, and two-second
read/write deadlines. Requests and responses must be exact canonical envelopes. Status remains
available when stale; proof queries fail closed with `RpcError::Stale`. Pages contain at most four
records and use the final returned key as the exclusive cursor for the next request.

`verify_query_record` now provides that semantic boundary. State records verify the object and
sparse proof against the cryptographically finalized post-state. Action records recompute the
canonical action identifier and both finalized ordered action roots from a bounded
`ActionSetProof`. Receipt records reuse the finalized receipt verifier and require the exact
committed root, height, and state transition. The durable index rejects any record that fails.

`activechain-rpc-node <rpc-index-snapshot> [bind-address]` serves the durable index continuously.
It defaults to the documented local RPC port `127.0.0.1:49151`; malformed connections are rejected
without terminating the service.

Operators may additionally configure free, allowlisted, or prepaid metered service without
changing the proof contract. See [configurable RPC access economics](rpc-access-economics.md).
