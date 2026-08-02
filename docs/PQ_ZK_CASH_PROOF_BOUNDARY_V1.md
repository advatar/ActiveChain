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
ingress. The original composed verifier re-runs host ML-DSA-44 verification for compatibility. The
`AuthorizedCashSessionMlDsaStarkProof` boundary instead composes the session proof with the complete
ML-DSA tables: canonical decoding, `tr` and `mu` hashing over the exact cash signing payload,
`ExpandA`, verifier reconstruction, and final challenge equality. Verification binds both proofs
to the same envelope and key commitment without calling host signature verification.

Cash proof aggregation uses a canonical four-level statement (microbatch, partition, cash slot,
and global transition). Every level binds the ordered child-proof commitments, exact partition
ownership, contiguous pre/post roots, applied/rejected counts, and checked resource totals. The
composed verifier checks the supplied child bytes against those commitments. Recursive in-circuit
verification of the child proofs remains a separate open gate and is not implied by this format.

Formal assurance must state circuit bounds, field-width assumptions, transcript domains, recursive
composition limits, and trusted setup/parameter provenance. The reference CashAIR re-execution
path remains the development oracle until the mandatory-proof profile is activated.
