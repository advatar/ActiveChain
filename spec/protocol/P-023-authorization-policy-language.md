# P-023: Authorization Policy Language

- Status: Draft 0.1
- Protocol version: Development
- Issue: <https://github.com/advatar/ActiveChain/issues/3>

## 1. Scope

This revision specifies the bounded Authorization Policy Language (APL), its canonical typed abstract syntax, the facts admitted to evaluation, deterministic work metering, effect combination, and returned obligations. Text parsing, policy authoring syntax, proof verification, credential verification, capability-chain validation, and obligation settlement are separate layers.

Consensus evaluates only a validated `PolicySetV1` against a validated `PolicyRequestV1`. The evaluator performs no I/O, clock reads, cryptography, storage access, dynamic dispatch, recursion, or external function calls.

## 2. Language version and bounds

APL language version 1 has these structural bounds:

```text
rules per policy                    <= 32
predicates per rule                 <= 16
obligations per permit rule         <= 4
credential-schema facts per request <= 32
capability facts per request         <= 32
approval-role facts per request      <= 16
```

Every bound MUST be checked before allocation proportional to attacker-controlled input. A policy with no rules is valid and denies every request. A rule with no predicates matches every request.

## 3. Canonical policy AST

A policy is an ordered list of rules. Each rule contains one effect, an ordered conjunction of predicates, and an ordered list of obligations.

Effects are `Permit` and `Forbid`. Version 1 predicates are:

- actor equality;
- action equality;
- resource-selector containment;
- value upper and lower bounds;
- height upper and lower bounds;
- presence of a verified credential-schema commitment;
- presence of a verified capability identifier;
- a minimum verified approval count for one role commitment;
- freeze-state equality; and
- declared-purpose equality.

Approval minima MUST be non-zero. Forbid rules MUST NOT contain obligations. Policy order is semantically observable only through returned permit obligations; effect combination itself is order-independent.

## 4. Authorization request

The request contains only deterministic transition context and facts already verified by upstream protocol components:

```text
actor, action, exact resource, height, value, freeze state,
optional declared purpose,
credential-schema commitments,
capability identifiers,
approval role/count facts
```

Credential schemas and capability identifiers MUST be strictly increasing and duplicate-free. Approval facts MUST be strictly increasing by role; zero counts are omitted and rejected if encoded. These requirements give every mathematical fact set exactly one version-1 representation.

A private actor is represented by a commitment. A private credential contributes only its schema commitment after proof verification. The evaluator MUST NOT receive undisclosed credential attributes, private keys, proof witnesses, wall-clock time, or network-derived facts.

## 5. Predicate semantics

All predicates are total. Equality compares canonical typed values. Numeric comparisons use unsigned integer order and cannot overflow. `ResourceMatches(selector)` is true exactly when the request's exact object selector is a subset of `selector`. Set membership uses the canonical verified fact sets. A missing approval role has count zero. A missing declared purpose does not equal any purpose commitment.

Predicates in a rule are conjoined. The implementation MUST evaluate every predicate even after one has returned false.

## 6. Decision semantics

Let `P` mean at least one permit rule matches and `F` mean at least one forbid rule matches. The normative decision table is:

| P | F | Result |
|---|---|---|
| false | false | Deny |
| false | true | Deny |
| true | false | Permit |
| true | true | Deny |

Thus absence of a permit is default deny, and any matching forbid overrides every permit. All matching-rule counts are reported. A denied decision MUST contain no obligations, including when permit rules matched before an overriding forbid.

## 7. Deterministic metering

Evaluation charges one step for each rule visited and one step for each predicate visited:

```text
steps = rule_count + sum(rule.predicate_count)
```

The maximum is 544 steps. Work does not depend on predicate truth values, matching effects, or where a rule appears. Version 1 implementations MUST NOT short-circuit a predicate conjunction or stop after a forbid.

## 8. Obligations

Matching permit rules contribute obligations in policy order and then rule-local order. Version 1 obligations are:

- decrement a capability budget;
- consume a single-use capability;
- emit an audit commitment;
- require an approval role and non-zero threshold during settlement;
- delay settlement until a height; and
- restrict output disclosure to a policy commitment.

At most 128 obligations can be structurally produced. The evaluator returns obligations but does not apply them. The enclosing state transition MUST validate and apply all obligations atomically with the authorized action. Unsupported, failed, or partially applied obligations abort the transition.

Version 1 does not deduplicate or merge obligations. Repetition is intentional and MUST be preserved because two decrements are observably different from one.

## 9. Canonical top-level values

The registered canonical values are:

```text
PolicySetV1       type 0x0040, schema 1, max body 35,043 bytes
PolicyRequestV1   type 0x0041, schema 1, max body  4,078 bytes
PolicyDecisionV1  type 0x0042, schema 1, max body  8,327 bytes
```

Decoded decisions MUST be consistent with the effect table, matching-rule bound, metering bound, and deny-without-obligations rule. Canonical decoding rejects unsupported language versions, invalid enum tags, excess lengths, duplicate or unordered facts, forbidden obligations, zero thresholds, inconsistent decisions, and trailing bytes.

## 10. Authorization composition

APL is one mandatory term in the complete authorization intersection. A permit does not by itself prove actor authentication, credential validity, capability attenuation, non-revocation, current budget availability, state-version freshness, or successful obligation settlement. The enclosing transition MUST require all applicable terms:

```text
authenticated actor
AND verified request facts
AND valid non-revoked authority
AND APL Permit
AND no explicit protocol forbid
AND atomic obligation settlement
```

No upstream component may insert an unverified fact into `PolicyRequestV1`.

## 11. Errors and abort behavior

Construction and canonical decoding return typed validation failures and no partial policy, request, or decision. Evaluation itself is total for validated inputs and has no error path. Allocation failure and host failure are outside the protocol result and MUST NOT be reinterpreted as Permit.

## 12. Test vectors and formal properties

The frozen APL vector contains one policy, request, and resulting decision with their canonical bodies, envelopes, and commitments. Unit and property tests MUST cover malformed bounds, canonical fact ordering, every predicate family, default deny, forbid precedence, obligation ordering, round trips, and truth-table equivalence.

The executable Lean reference model defines the same effect combiner and MUST prove:

```text
combine false false = Deny
combine P true = Deny
combine P F = Permit <-> P = true AND F = false
```

Rust tests exhaustively compare all Boolean effect combinations with the reference truth table.

## 13. Compatibility

New predicate or obligation variants require an unused discriminant and a new language/schema version unless older decoders can reject them without changing any historical decision. Limits, metering, effect precedence, canonical ordering, and existing variant meaning MUST NOT change retroactively.

## 14. Implementation notes (non-normative)

The reference Rust crate is `no_std`, forbids unsafe code, and allocates only structurally bounded vectors. The Lean model is intentionally smaller than the wire implementation: it independently captures the consensus-critical effect algebra rather than attempting to verify Rust parsing or memory behavior.
