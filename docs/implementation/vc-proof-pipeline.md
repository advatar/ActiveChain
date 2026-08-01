# TLS-derived VC to ActiveChain proof pipeline

Status: ActiveChain canonical evidence and predicate-admission boundary implemented; cross-repo
wallet/device conformance and independent review remain open under issue #169.

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

The canonical `TlsCredentialEvidenceV1` envelope contains only notary, server, transcript,
disclosed-field, holder, schema, status, freshness, and optional issuer-authorization commitments.
It has no field capable of carrying a source transcript or account identifier. The assurance enum
is ordered but not self-asserting: issuer-upgraded and regulated classes are structurally invalid
without a nonzero issuer-authorization commitment, while lower classes must not carry one.

`admit_tls_credential_predicate` requires the predicate claims commitment to equal the commitment
of the complete evidence envelope, then independently checks holder, schema, freshness, minimum
assurance, chain, audience, action, predicate expiry, and the hidden-value proof callback. A
holder/self-issued envelope therefore cannot satisfy an issuer-upgraded or regulated policy.

## Proof-of-funds profile

The source schema must make currency, units, decimals, institution/account scope, aggregation rules,
observation time, and freshness window unambiguous. A presentation may prove:

- balance is at least a threshold;
- balance lies in a bounded range;
- currency or asset equals an allowed value;
- evidence comes from an allowed institution set;
- observation is fresh enough for the policy;
- several credentials satisfy an explicitly declared aggregation rule.

Identity credentials use the same predicate model. A holder may prove age is at least a threshold
without disclosing a birth date or exact age, or prove that nationality/jurisdiction is outside (or
inside) a canonical policy set without disclosing the actual country. For example, a policy may
request `nationality NOT IN {US, KP}` rather than the nationality claim.

Country predicates bind a frozen country-code registry revision and the exact ordered policy-set
commitment. Missing, unknown, historic/aliased, or multiple nationality values fail closed unless
the policy explicitly defines their semantics. Wallet consent must warn when a permitted or denied
set is so small—or repeated verifier queries can be intersected—such that the hidden value may be
inferred despite zero-knowledge proof generation.

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
Set proofs additionally require complement correctness, canonical set encoding, registry-revision
binding, and resistance to policy substitution and repeated-query intersection.
TLSNotary soundness, notary and issuer authorization, credential-status provenance, ZK-system
soundness, trusted clocks, and device key protection remain explicit assumptions until separately
refined or verified. Every assumption and unproved composition gap must remain machine-indexed and
visible in release qualification.

## Finalized predicate receipt

`CredentialPredicateReceiptV1` is the transcript-free offline receipt for an admitted predicate.
Its constructor recomputes the complete TLS evidence and predicate commitments, requires the same
holder and schema, checks both freshness windows, and copies—not re-declares—the evidence assurance,
status, and optional issuer authorization. It additionally binds the verifier, proof-system version,
policy, nullifier, verification height, and non-regressing finalized height. The receipt contains no
raw transcript, account identifier, full balance, or disclosed attribute. A canonical receipt is a
binding artifact; consumers must still verify its finalized membership/finality evidence.

After cryptographic proof and finality verification, application admission passes the bound
receipt, evidence, predicate, and exact non-membership witness to
`DurableCredentialReceiptJournal`. The journal consumes the receipt's policy-scoped nullifier
through the canonical constant-size `NullifierSet`, writes and synchronizes the next canonical
envelope, and atomically replaces durable state before advancing memory or acknowledging success.
Replays, stale or substituted witnesses, mismatched evidence, and corrupt restart state fail
closed. The journal deliberately does not replace proof or finality verification; it provides the
durable exactly-once boundary after those checks succeed.
