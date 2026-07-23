# Configurable RPC access economics

ActiveChain RPC access is an operator service, not a consensus rule. A node may serve proofs for
free, restrict service to operator-approved clients, or sell prepaid request capacity. In every
mode, the returned state, action, receipt, and finality material uses the same proof-bearing RPC
contract and remains independently verifiable by the client.

## Modes

- `Free` accepts revision-1 anonymous requests unchanged. An operator may optionally publish a
  canonical free offer through the access wrapper.
- `Allowlist` requires an operator-signed zero-price grant tied to a client ML-DSA-44 public key.
- `Prepaid` requires an operator-signed grant whose paid amount covers its purchased units under
  the signed offer.

Status and offer discovery are never metered. `Get` has a configurable fixed unit cost. `List`
costs a configurable base plus a per-requested-item cost. Units are charged before query execution,
including not-found results, so unauthenticated work cannot exhaust operator resources.

## Authenticated offers and grants

Non-free `RpcAccessTerms` include the chain and operator identities, operator ML-DSA-44 public key
and signature, access mode, quote expiry, settlement asset and recipient, unit price, request cost
schedule, and maximum grant lifetime.

Clients must obtain the expected operator identity through a trusted directory or an explicit pin
and call `verify_access_terms`. Transport discovery alone is not an identity root.

An `RpcAccessGrant` embeds the exact signed offer under which it was issued. It also binds the
client key, grant identifier, validity interval, purchased units, paid amount, and an opaque
nonzero settlement reference. Embedding the offer lets an operator publish new prices without
invalidating unexpired grants purchased under an older signed offer.

The settlement reference may identify a finalized ActiveChain receipt, an invoice, a subscription,
or an allowlist record. Settlement verification happens before the operator signs a grant. The
serving node trusts only the resulting operator signature; it never accepts a client's payment
claim directly.

`RpcAccessGrant::signing_payload_for` and `RpcAccessTerms::signing_payload` support an HSM or other
external signer. Signed terms are persisted with `write_access_terms`. Clients use
`RpcAccessAuthorization::signing_payload_for` to bind the grant ID, monotonic sequence, and exact
canonical request commitment.

Operators should use a distinct client key per service if cross-service linkability is undesirable.

## Durable metering

For each accepted non-free request, `RpcAccessController` verifies the time bounds, embedded offer,
operator and grant signatures, paid-unit relationship, client signature, exact request commitment,
next sequence, and remaining budget.

The next sequence and spent units are written through a canonical, integrity-tagged,
temp-file/fsync/rename snapshot before the query is served. A failed write changes no in-memory
usage. Restart, replay, exhaustion, truncation, and corruption fail closed.

Usage snapshots bind the chain, operator identity, and operator key rather than one price sheet.
This permits signed offer rotation while retaining replay and budget history.

## Node configuration

The node keeps free access as its default:

```text
activechain-rpc-node <index-snapshot> [bind-address]
```

To publish a free offer:

```text
activechain-rpc-node <index-snapshot> <bind-address> <access-terms>
```

Allowlist and prepaid modes require durable usage:

```text
activechain-rpc-node <index-snapshot> <bind-address> <access-terms> <usage-snapshot>
```

If a non-free usage snapshot does not exist, the node creates it atomically. Otherwise it loads
and validates it. A file with a different chain/operator/key scope or invalid signature is
rejected. Removing the terms argument deliberately restores legacy free service and is a
security-sensitive configuration change.

RPC charging does not make the node, index, or proofs authoritative. Clients must still verify
finality and query proofs. Access revenue is not protocol fee revenue unless a separate finalized
transaction explicitly makes it so.
