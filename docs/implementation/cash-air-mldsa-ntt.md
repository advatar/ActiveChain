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

The challenge-product proof validates the fixed ML-DSA-44 challenge shape (exactly 39 nonzero
coefficients, each `+1` or `-1` in `Z_q`), proves its forward NTT, composes the `t1_2d_hat`
precomputation, and proves all four `c_hat * t1_2d_hat` products. Deriving that sparse polynomial
from the challenge seed through SHAKE rejection sampling remains an explicit subsequent boundary.

The reconstruction proof now composes the complete four-polynomial verifier arithmetic path:
`z` range validation and forward NTT, `A_hat * z_hat`, `c_hat * t1_2d_hat`, modular subtraction,
inverse NTT, and `UseHint`. The externally supplied matrix and sparse challenge remain public and
fully bound; deriving them from `rho` and the challenge seed through SHAKE, then proving the final
challenge-hash equality, are the remaining end-to-end cryptographic boundaries.

The specialized Keccak AIR now also proves bounded SHAKE256 XOF output up to 16,384 bytes in one
ordered trace. It binds the padded absorption chain and every additional squeeze permutation,
providing the variable-length transcript boundary required by matrix expansion and challenge
rejection sampling rather than treating bytes beyond the first 48 as unproved host output.

`ExpandA` uses SHAKE128, so its proof uses the same ordered Keccak AIR with the FIPS SHAKE128
168-byte rate. For each of the 16 `rho || column || row` streams it proves the exact XOF prefix,
applies Algorithm 30's 23-bit rejection rule, and binds the first 256 accepted coefficients. The
bounded proof supports the specified fallback beyond the initial 840 bytes instead of assuming the
overwhelmingly likely fast path.
