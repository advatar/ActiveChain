# CashAIR ML-DSA forward NTT table

The first ML-DSA-44 arithmetic table constrains the exact 256-coefficient forward NTT from FIPS
204 Algorithm 41 over `q = 8,380,417`. Its 1,024 butterflies use the Appendix B bit-reversed powers
of `zeta = 1753`.

For every butterfly the AIR proves the modular product, addition, and subtraction relations with
explicit quotient witnesses. Addition and subtraction wrap selectors are Boolean constrained. The
verifier rejects coefficients outside `Z_q` and binds every input, intermediate, twiddle, quotient,
and output field element through public assertions. A separate inverse-NTT implementation checks
the forward result round-trips exactly.

This explicit binding is intentionally conservative and currently expensive: the verifier
reconstructs the complete public butterfly schedule. It establishes the arithmetic table before a
reviewed cross-table commitment/permutation argument replaces that development boundary. The table
is not yet enabled at validator ingress and does not make an end-to-end in-circuit ML-DSA claim.

Remaining verifier tables include signature/key decoding and range checks, SHAKE-derived matrix and
challenge sampling, vector/matrix NTT products, inverse NTT, hint application, infinity norms, and
the final challenge equality, followed by cross-table composition with the session statement.

The companion `MultiplyNTT` table now constrains all 256 coefficient-wise products used by FIPS
204 NTT-domain polynomial multiplication. Each row proves `left × right = output + q × quotient`,
and the verifier binds both operands, every quotient, and the complete output. Vector dot-product
accumulation and matrix-row composition remain open rather than being inferred from independent
pointwise proofs.
