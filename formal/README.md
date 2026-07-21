# ActiveChain formal-verification program

Formal verification is a launch gate. These artifacts are scoped models with explicit assumptions;
they are not a certificate that the complete implementation is correct.

## Tooling

- Lean 4 models executable semantics and algebraic invariants.
- Tamarin models adversarial protocol traces, authentication, replay, compromise, and ordering.
- Rust differential fixtures compare selected executable Lean tables with the implementation.

## Current proof domains

| Domain | Tool | Primary artifact | Status |
| --- | --- | --- | --- |
| APL, credentials, objects, ObjectVM, state tree, nonce | Lean 4 | `formal/lean/ActiveChain/` | scoped models build and differential fixtures pass |
| wallet-agent HITL and replay | Tamarin | `formal/tamarin/activechain_wallet.spthy` | three scoped safety lemmas proved |
| consensus and validator networking | Tamarin | `formal/tamarin/activechain_consensus.spthy` | in progress |
| native cash and reward supply | Lean 4 | `formal/lean/ActiveChain/Cash.lean` | scoped invariants proved |
| identity lifecycle and delegation | Tamarin | `formal/tamarin/activechain_identity.spthy` | in progress |
| DA reconstruction and light-client trust | Lean 4 | `formal/lean/ActiveChain/DA.lean` | scoped invariants proved |

## Local reproduction

```bash
(cd formal/lean && lake build)
tamarin-prover formal/tamarin/activechain_wallet.spthy --prove --derivcheck-timeout=60
```

A proof run is accepted only when every declared lemma is `verified`, all well-formedness checks
pass, and the proof-scope document records the model assumptions and implementation mapping.
Falsified lemmas and counterexample traces are evidence to fix the model, specification, or code;
they must never be hidden by weakening a property without documenting the change.

## Unverified boundary

The program does not yet establish end-to-end correctness of the Rust implementation, the
cryptographic primitives, liveness under arbitrary scheduling, data availability, mobile OS
security, FFI memory safety, economics under every governance transition, or deployment
configuration. Independent formal-methods and security review remains mandatory before any
non-developmental or value-bearing launch.
