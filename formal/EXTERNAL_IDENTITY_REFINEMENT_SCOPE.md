# External identity refinement and privacy proof scope

Status: bounded production-linked model for issues #438–#447.

## Claims and commands

`formal/lean/ActiveChain/ExternalIdentity.lean` proves the named theorems
`issuer_authenticity`, `schema_integrity`, `holder_non_transferability`, `status_freshness`,
`context_and_replay_safety`, `no_authority_inflation`, `assurance_monotonicity`,
`disclosure_minimization`, `forbid_dominates`, and `declared_trace_only`.

Reproduce with:

```sh
cd formal/lean
lake build ActiveChain externalIdentityTable
lake env lean ExternalIdentityTable.lean
```

The executable table is compared byte-for-byte with
`testing/vectors/external-identity-refinement-v1.tsv` by the targeted Rust admission test.
`scripts/check-identity-bridge-corpus.py --self-test` independently connects the model cases to the
shared canonical profile, binding, status, and adversarial corpus consumed by ActiveChain,
VCIssuer, and EUWallet.

## Threat representation

Issuer/trust substitution, schema/rulebook confusion, malicious holder/device transfer, malicious
or equivocal status publisher, malicious verifier context substitution, replay, assurance
promotion, over-disclosure, missing capability/approval, and explicit forbid are separate model or
shared-corpus cases. The public trace projects only issuer/schema/status/policy commitments and the
admission result. Unlinkability assumes high-entropy pairwise/private witnesses, no issuer-verifier
collusion, protected wallet storage, and no correlation through repeated rare queries or network
metadata; those limitations are user-visible in P-097/P-102.

## Exact evidence boundary

Lean proves the Boolean implication structure for all inputs, not cryptographic algorithms,
parsers, Rust compiler correctness, OS persistence, transport confidentiality, or the entropy of
private witnesses. Rust tests provide bounded implementation-to-model parity for the canonical
mapping, issuer/subject binding, status, adapter replay, opaque admission, P-023 injection, and APL
intersection. The shared corpus provides finite trace coverage, not a universal compiler-level
refinement theorem. Independent interoperability, cryptographic, privacy, and certification review
remain release gates.

## Trusted code base and counterexamples

Trusted inputs are the pinned cryptographic verifier results, finalized ActiveChain roots, collision
resistance of registered hashes, correct platform user-presence result, and the Lean kernel/toolchain.
During implementation, the caller-decodable presentation envelope was found insufficient as an
adapter-execution proof; #443 introduced the opaque non-deserializable token before admission.
