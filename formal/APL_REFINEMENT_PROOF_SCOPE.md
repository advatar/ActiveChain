# APL refinement proof scope

The APL effect proof is no longer limited to the frozen four-row truth table.
`ActiveChain.Apl.evaluatePermitIff` quantifies over arbitrary lists of observed
rules and proves that evaluation permits exactly when at least one permit rule
matches and no forbid rule matches. The inductive `collectEffectsSpec` theorem
connects the executable fold to that order-independent specification.

The production differential test enumerates every sequence of permit/forbid and
matched/unmatched observations through length six (5,461 policies). It constructs
real bounded `PolicySet` and `PolicyRequest` values and compares the production
evaluator with an independent fold for the decision, matched-rule counts,
metering, obligation order, default deny, and forbid clearing.

This result covers the complete APL v1 effect algebra and the production rule
loop. Predicate-family semantics remain covered by Rust unit tests, not by Lean:
the mapping from protocol identifiers, resource selectors, request facts, and
integer comparisons into each Boolean rule observation is still a refinement
boundary. Canonical codec correctness and the cryptographic provenance of request
facts are separate proof domains.
