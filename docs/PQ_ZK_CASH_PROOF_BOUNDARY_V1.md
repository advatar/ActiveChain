# PQ-ZK and CashAIR proof boundary v1

CashAIR and privacy proofs are evidence about a canonical transition; they are not authorization
or finality by themselves. A proof statement commits to chain/genesis, protocol revision, action
ID, input/output Coin Cell roots, fee/resource limits, nonce, and policy context.

The verifier first checks canonical framing and public-input domain separation, then the proof,
then the PQ authorization and finalized parent context. A valid proof with a mismatched action,
root, signer suite, or genesis is rejected. A missing, malformed, unsupported, or verifier-version
mismatched proof is a typed failure and never advances finality or credits value.

The session-budget proof binds a domain-separated commitment to the exact canonical
`AuthorizedCashTransferV1` envelope and the finalized ML-DSA-44 verification key used by wallet
ingress. Its composed verifier re-runs real ML-DSA-44 verification before accepting the STARK.
This closes envelope/key substitution at the proof boundary; it is not a claim that ML-DSA
arithmetic is constrained inside the session AIR.

Formal assurance must state circuit bounds, field-width assumptions, transcript domains, recursive
composition limits, and trusted setup/parameter provenance. The reference CashAIR re-execution
path remains the development oracle until the mandatory-proof profile is activated.
