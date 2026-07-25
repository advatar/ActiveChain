# dBrowser development RPC contract v1

The development RPC exposes a bounded, authenticated query surface for light clients and
dBrowser. `status` returns chain ID, genesis commitment, protocol revision, finalized height and
block hash, health/staleness, supported proof profiles, and the server's verifier revision.

State, action, receipt, and owner/asset queries return finalized records with their proof bytes,
query key, finality identity, and exact schema/profile revision. A response is not authoritative
without a proof; clients must treat timeout, stale status, unsupported proof, and incomplete proof
as explicit non-success states.

Pagination is deterministic by canonical key and bounded by the advertised page limit. Transport
authentication identifies the operator and client, but does not replace proof verification. The
contract is testnet/development-only until independent SDK and operational qualification gates pass.
