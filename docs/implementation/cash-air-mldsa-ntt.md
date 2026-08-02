# CashAIR ML-DSA forward NTT table

The first ML-DSA-44 arithmetic table constrains the exact 256-coefficient forward NTT from FIPS
204 Algorithm 41 over `q = 8,380,417`. Its 1,024 butterflies use the Appendix B bit-reversed powers
of `zeta = 1753`.

For every butterfly the AIR proves the modular product, addition, and subtraction relations with
explicit quotient witnesses. Addition and subtraction wrap selectors are Boolean constrained. The
verifier rejects coefficients outside `Z_q` and binds every input, intermediate, twiddle, quotient,
and output field element through public assertions. The inverse table constrains the reverse FIPS
204 butterfly schedule and composes its mandatory `256^-1 mod q` normalization through the
separately proved `MultiplyNTT` table. Targeted tests prove the forward/inverse round trip and reject
substituted inputs, outputs, and out-of-range coefficients.

This explicit binding is intentionally conservative and currently expensive: the verifier
reconstructs the complete public butterfly schedule. It establishes the arithmetic table before a
reviewed cross-table commitment/permutation argument replaces that development boundary. The table
is not yet enabled at validator ingress and does not make an end-to-end in-circuit ML-DSA claim.

The decoding table now binds the exact ML-DSA-44 public-key and signature bytes, constrains all
10-bit `t1` and 18-bit `z` unpacking, proves the strict FIPS 204 `z` infinity-norm bound, and rejects
non-canonical sparse-hint cuts, ordering, weight, and padding. It exposes `rho`, the challenge seed,
decoded polynomials, and the hint bitmap for subsequent tables.

Remaining verifier tables include SHAKE-derived matrix and challenge sampling, the final challenge
equality, and cross-table composition
with the session statement.

The companion `MultiplyNTT` table now constrains all 256 coefficient-wise products used by FIPS
204 NTT-domain polynomial multiplication. Each row proves `left × right = output + q × quotient`,
and the verifier binds both operands, every quotient, and the complete output. The ML-DSA-44 vector
accumulation proof composes four such proofs for a matrix row, then proves the three coefficient-wise
reduced additions with Boolean wrap witnesses. The matrix-vector proof composes all four fixed
ML-DSA-44 rows. SHAKE-derived matrix construction and binding remain open rather than being inferred
from an independently supplied matrix.

The verifier precomputation proof constrains every decoded `t1` coefficient to its canonical
10-bit range, composes coefficient-wise multiplication by `2^13` modulo q, and proves the forward
NTT of all four scaled polynomials. This supplies the exact cached `t1_2d_hat` operand used by FIPS
verification; multiplication by the sampled challenge remains a separate table.

The challenge-product proof derives the fixed ML-DSA-44 challenge from the decoded 32-byte
`c_tilde` seed. Its bounded SHAKE256 proof binds the exact Algorithm 29 stream, including the first
eight sign bytes, rejection-sampled swap indices, and all 39 signed terms. It then proves the
challenge's forward NTT, composes the `t1_2d_hat` precomputation, and proves all four
`c_hat * t1_2d_hat` products. A caller can no longer substitute an independently supplied sparse
polynomial.

The reconstruction proof now composes the complete four-polynomial verifier arithmetic path:
`z` range validation and forward NTT, `A_hat * z_hat`, `c_hat * t1_2d_hat`, modular subtraction,
inverse NTT, and `UseHint`. The matrix and sparse challenge are now derived from `rho` and
`c_tilde` through proved SHAKE streams. The final-challenge composition canonically packs all four
`w1` polynomials at six bits per coefficient, proves SHAKE256 over the exact 64-byte `mu` plus
768-byte `w1Encode(w1)` transcript, and requires its 32-byte output to equal the decoded signature
`c_tilde`. The cross-table layer below connects these tables to decoded key/signature bytes; the
session statement remains the activation boundary.

The cross-table verifier now closes the standalone ML-DSA-44 boundary. It accepts one canonical
1,312-byte public key, 2,420-byte signature, and message payload; proves key/signature decoding;
proves `tr = SHAKE256(pk, 64)` and the normal-mode empty-context
`mu = SHAKE256(tr || 0x00 || 0x00 || payload, 64)` transcript; derives `ExpandA(rho)`; and feeds the
decoded `t1`, `z`, hints, and `c_tilde` through reconstruction and final-challenge equality. A real
deterministic `ml-dsa 0.1.1` signature exercises the complete composition. Binding this composed
proof object into the session AIR's authorization commitment remains a separate activation step.

Real signatures can legitimately omit the rare `UseHint` increment/decrement wrap branches. The
UseHint table therefore appends fixed valid branch-exercising rows after its 1,024 verifier rows,
keeping every declared Boolean constraint algebraically nonconstant without changing or weakening
the public verifier rows.

The specialized Keccak AIR now also proves bounded SHAKE256 XOF output up to 16,384 bytes in one
ordered trace and accepts bounded XOF messages up to 2,048 bytes, enough for both the 832-byte final
challenge transcript and the 1,312-byte public-key hash used to derive `tr`. It binds the padded
absorption chain and every additional squeeze permutation, providing the variable-length transcript
boundary required by matrix expansion and challenge rejection sampling rather than treating bytes
beyond the first 48 as unproved host output.

`ExpandA` uses SHAKE128, so its proof uses the same ordered Keccak AIR with the FIPS SHAKE128
168-byte rate. For each of the 16 `rho || column || row` streams it proves the exact XOF prefix,
applies Algorithm 30's 23-bit rejection rule, and binds the first 256 accepted coefficients. The
bounded proof supports the specified fallback beyond the initial 840 bytes instead of assuming the
overwhelmingly likely fast path.
