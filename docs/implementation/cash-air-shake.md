# CashAIR SHAKE table

CashAIR uses the maintained Plonky3 Keccak AIR for the bit-level Keccak-f[1600] constraints. The
ActiveChain wrapper adds 200 public BabyBear values: four exact 16-bit limbs for each of the 25
input lanes and each of the 25 output lanes. First-row and final-round constraints bind those values
to the permutation trace, preventing an otherwise valid proof for an unrelated Keccak state.

`prove_shake256_384` applies the SHAKE256 rate, `0x1f` suffix, terminal `0x80` padding, absorption,
and 384-bit squeeze. Each absorbed block has its own public-state-bound permutation proof; the next
block starts from the prior constrained output. Messages are bounded to 512 bytes, which covers the
authenticated Coin Cell leaf, empty-leaf, internal-node, and count-root transcripts.

Tests compare one- and two-block proofs byte-for-byte with RustCrypto SHAKE256. They also prove the
exact transcript bytes exported by the cash accumulator for canonical leaves, depth-bound internal
nodes, and count-bound roots. Message, block-boundary, lane, and digest substitutions fail.

This completes the standalone specialized SHAKE primitive, not issue #78. A full sparse path can
contain hundreds of permutations. The remaining step is a batched trace plus a sound cross-table
argument connecting every exported `(pre_state, post_state)` tuple to the ordered mutation-path
table. Until that connection exists, direct SHAKE recomputation remains authoritative and the
CashAIR membership gate stays open.
