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
basic composed verifier checks supplied child bytes against those commitments. The proof-leaf
verifier additionally accepts exactly one authorized payment per leaf and recomputes every child
field: it verifies the complete session/ML-DSA proof, verifies the partition-authenticated CashAIR
receipt, opens the exact one-transfer batch commitment, derives chain and height, derives the
coordinator partition from the first input under the proved partition count, and recomputes the
fixed resource charge. Cross-partition state mutations remain bound inside that receipt. Recursive
in-circuit verification of the child proofs remains a separate open gate and is not implied by this
host-composed verifier.

The CashAIR parent statement itself binds the chain identifier, batch commitment, execution height,
and partition count in dedicated public-input trace columns at both trace boundaries. These values
are not trusted from the receipt wrapper. The session verifier also rejects a witness unless its
chain, signer, session, height window, amount, and fee match the exact authorized transfer.

Formal assurance must state circuit bounds, field-width assumptions, transcript domains, recursive
composition limits, and trusted setup/parameter provenance. The reference CashAIR re-execution
path remains the development oracle until the mandatory-proof profile is activated.
