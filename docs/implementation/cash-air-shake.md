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

The implemented batch uses one Keccak trace and committed preprocessed binding columns. The verifier
derives the ordered permutation input/output tuples from the mutation transcripts, constructs the
same binding table, and verifies its commitment with the STARK. Every first and final round is
constrained against its assigned slot; power-of-two padding slots are constrained to the zero-state
permutation. This provides ordered equality directly and avoids relying on a fixed-challenge or
unimplemented global permutation argument.

`prove_shake256_384_batch` and `verify_shake256_384_batch` expose that ordered table for a bounded
message sequence. The remaining issue #78 work is to derive that sequence inside the ordered
mutation-path adapter and bind its resulting roots into the parent CashAIR public inputs.

The authenticated adapter now expands every ordered mutation into its exact pre-state leaf, 384
depth-bound nodes, count-bound root, post-state leaf, 384 depth-bound nodes, and count-bound root.
It rejects a derived terminal root that differs from the mutation witness and feeds the complete
ordered sequence to the single batch proof. A full-depth mutation contains 772 SHAKE messages, so
validator ingress remains disabled until benchmark data establishes a safe mutation cap and memory
budget and the resulting roots are bound into the parent CashAIR proof.
