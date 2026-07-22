# Authenticated Coin Cell accumulator

The legacy `CoinCellSetRoot` remains the frozen commitment to the complete ordered set. CashAIR
membership evidence additionally uses `AuthenticatedCoinCellRoot`, a domain-separated binary
sparse Merkle accumulator keyed by all 384 bits of the canonical Coin Cell identifier. The root
also binds the exact live-cell count.

Every leaf commits the canonical Coin Cell record and verifies that its identifier is derived from
its `CoinCellOrigin`. Empty leaves, internal nodes, and the count-bearing root have distinct SHAKE
transcripts. A mutation carries exactly 384 siblings and proves either membership-to-absence,
absence-to-membership, or a canonical same-key replacement. The verifier recomputes both roots,
checks the count delta, and rejects noncanonical record identifiers.

`CoinCellTransitionWitness` chains a strictly ID-ordered, bounded sequence of mutations. A single
cash transfer admits at most all declared inputs, its fee reserve, and its two outputs. Accepted
authenticated CashAIR rows carry one exact transition; rejected rows carry none and retain the
prior root. The direct verifier independently reexecutes the transfer and reconstructs the expected
witness, so missing cells, duplicate or reordered mutations, substituted paths/records/roots, and
wrong execution context fail closed.

This is the local-proof foundation, not completion of the specialized AIR gate. The SHAKE path
hashes and ordered root chain still need to be arithmetized in the transparent proof before issue
#76 and the parent CashAIR phase can be closed.
