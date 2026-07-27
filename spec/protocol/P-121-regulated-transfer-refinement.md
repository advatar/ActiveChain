# P-121 implementation/formal refinement boundary

This note maps the concrete operator admission helper to the executable Lean model in
`formal/lean/ActiveChain/Payments.lean`.

| Concrete admission predicate | Lean predicate/model | Required conformance evidence |
|---|---|---|
| verifier callback returns false | `admitRegulated false ... = none` | `signature-failure` vector |
| evidence chain/action/profile/expiry match | `admitRegulated true ...` precondition | matching and expiry vectors |
| Travel Rule chain/action/asset/amount/expiry match | regulated-transfer binding precondition | substitution/expiry vectors |
| first valid nonce | `consumeNonce used nonce = some next` | `first-use` vector |
| duplicate nonce | `regulatedNonceIsOneShot` | `replay` vector |
| persistence failure | durable journal returns error before replacing memory | restart/corruption tests |

The Lean model abstracts cryptographic verification as a Boolean assumption. Production Rust MUST
instantiate that assumption with the configured ML-DSA verifier and preserve the exact canonical
transcript. A passing formal theorem does not replace cryptographic implementation review or
Rust-to-model conformance testing.
