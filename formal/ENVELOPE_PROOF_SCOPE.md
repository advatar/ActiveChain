# Canonical envelope and FFI proof scope

`formal/lean/ActiveChain/Envelope.lean` is a dependency-free Lean 4 model of
the compatibility boundary frozen by P-110 and implemented by
`activechain-canonical-codec`, `activechain-verifier-api`,
`activechain-verifier-ffi`, and the current wallet session ABI.

## Mechanically checked claims

`lake build` checks, without `sorry`, `admit`, or custom axioms, that:

- successful inspection implies the 256 KiB envelope bound, a complete header
  and length prefix, the expected type and schema version, a minimal bounded
  length, an exactly sized body, and zero trailing bytes;
- wrong types, wrong versions, non-minimal lengths, wrong body lengths,
  oversized envelopes, and trailing bytes cannot be accepted;
- commitment success implies that the supplied hash of the selected domain and
  canonical body equals the expected digest, while an observed mismatch is
  rejected;
- combined envelope/commitment success implies both canonical-envelope
  validity and commitment binding to the body selected by that inspection;
- a null verifier pointer with non-zero length maps to stable error code 6,
  while a permitted pointer/length pair delegates to the safe inspector;
- variable commitment buffers obey the null-only-when-zero rule and the fixed
  48-byte digest pointer is mandatory; and
- the wallet session ABI can return success only when both fixed-size pointers
  are present and the session has not expired.

## Refinement boundary and non-claims

The Lean input records parser observations rather than reimplementing Rust's
byte cursor. The refinement obligation is to keep the Rust big-endian `u16`,
minimal `u32` ULEB128, body slicing, and `finish()` behavior aligned with these
observations; Rust unit tests and pinned malformed vectors exercise that link.

The arbitrary `hash` function makes commitment equality explicit without an
axiom. This proof does not establish SHAKE256 collision or preimage resistance.
Those remain standard cryptographic assumptions and require implementation
vectors plus independent review.

Lean cannot establish that a foreign non-null address actually points to a
readable allocation of the declared length. That is the C caller's safety
precondition. The proof covers the wrapper's expressible null/length gate and
the handoff to the safe Rust verifier; memory safety still requires ABI tests,
sanitizers/fuzzing, and review of every native binding.

This scope does not prove body-schema semantics, consensus finality, cash
economics, data availability, mobile UI intent display, or whole-system
security. Those have separate models and refinement gates.
