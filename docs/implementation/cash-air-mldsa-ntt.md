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

Remaining verifier tables include SHAKE-derived matrix and challenge sampling, full matrix-row
composition, the final challenge equality, and cross-table composition
with the session statement.

The companion `MultiplyNTT` table now constrains all 256 coefficient-wise products used by FIPS
204 NTT-domain polynomial multiplication. Each row proves `left × right = output + q × quotient`,
and the verifier binds both operands, every quotient, and the complete output. The ML-DSA-44 vector
accumulation proof composes four such proofs for a matrix row, then proves the three coefficient-wise
reduced additions with Boolean wrap witnesses. Full matrix construction and SHAKE-derived matrix
binding remain open rather than being inferred from an independently supplied row.
