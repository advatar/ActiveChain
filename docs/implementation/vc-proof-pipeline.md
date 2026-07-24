# TLS-derived VC to ActiveChain proof pipeline

Status: requirements and trust-boundary specification; tracked by issue #169.

## Ownership

`tlsn` produces portable, holder-bound evidence and may package a self-issued VC. `EUWallet`
validates, stores, labels, presents, deletes, recovers, and audits credentials under wallet-owned
consent. ActiveChain verifies a minimal, action-bound proof and records only the commitments,
nullifiers, policy result, and receipt needed for independent verification.

No layer may reinterpret the assurance supplied by the previous layer:

| Input | Permitted claim |
| --- | --- |
| Valid TLSNotary artifact | The committed HTTPS transcript came from the bound server/session under the declared notary assumptions. |
| Holder/self-issued VC | The holder key packaged the declared evidence and claims. It is not automatically third-party identity or regulated KYC. |
| Authorized issuer-upgraded VC | The named issuer attested the claims under its declared authorization, schema, status, and assurance framework. |
| ActiveChain ZK result | The committed credential of the declared assurance class satisfied the exact public predicate and action context. |

## Proof-of-funds profile

The source schema must make currency, units, decimals, institution/account scope, aggregation rules,
observation time, and freshness window unambiguous. A presentation may prove:

- balance is at least a threshold;
- balance lies in a bounded range;
- currency or asset equals an allowed value;
- evidence comes from an allowed institution set;
- observation is fresh enough for the policy;
- several credentials satisfy an explicitly declared aggregation rule.

The proof must not reveal the transcript, account identifier, unrelated transactions, exact balance
when a threshold is sufficient, or a reusable global holder identifier.

## Binding

The proof public inputs bind the credential commitment and assurance class to:

- ActiveChain chain ID and genesis commitment;
- asset or application domain and exact action;
- policy, schema, verifier, and proof-system revisions;
- verifier/audience and declared purpose;
- opaque challenge nonce, validity interval, and finalized credential-status reference;
- holder key or pairwise pseudonym and the policy-scoped nullifier.

A verifier must reject any substitution, replay, expired status, unknown issuer/notary authority,
unsupported schema, currency/unit ambiguity, or attempt to upgrade the assurance class.

## Formal release gates

The refinement chain is:

```text
authenticated TLS evidence
  -> typed VC claim semantics with explicit provenance
  -> circuit witness and public inputs
  -> verified predicate
  -> APL/authorization decision
  -> finalized receipt
```

Formal work must establish predicate soundness, no provenance escalation, holder/action/audience
binding, replay resistance, disclosure minimization, and the stated unlinkability boundary.
TLSNotary soundness, notary and issuer authorization, credential-status provenance, ZK-system
soundness, trusted clocks, and device key protection remain explicit assumptions until separately
refined or verified. Every assumption and unproved composition gap must remain machine-indexed and
visible in release qualification.
