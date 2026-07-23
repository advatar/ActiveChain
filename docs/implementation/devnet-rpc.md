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

The remaining issue #91 work is semantic: adapters must construct and verify state, action, and
receipt records against the finalized header rather than trusting opaque proof bytes. The public
network service must then be wired into the validator/indexer process.
