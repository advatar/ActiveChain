# Canonical Codec Kani Proof Scope

Status: bounded verification slice implemented and passing on 2026-07-21.

This slice runs Kani against the production `activechain-canonical-codec` crate. It does not use a
copied codec model. The proof harnesses are compiled only under `cfg(kani)` and exercise the same
`Encoder`, `Decoder`, `encode_envelope`, and `decode_envelope` functions used by the workspace.

## Pinned verifier

- `cargo-kani 0.67.0`
- Kani driver `0.67.0`
- Kani release bundle `kani-0.67.0-aarch64-apple-darwin`
- bundled CBMC `6.8.0`
- bundled Rust `nightly-2025-11-21-aarch64-apple-darwin`
- bundled `rustc 1.93.0-nightly (53732d5e0 2025-11-20)`

Kani 0.67.0 cannot load a package whose declared minimum Rust version is 1.97.1 because its bundled
compiler is Rust 1.93. The canonical-codec package therefore declares a package-specific Rust 1.93
minimum while the rest of the workspace remains pinned to Rust 1.97.1. Normal compilation, tests,
and clippy run with the workspace toolchain; Kani analyzes the actual crate with its bundled
toolchain.

Initial installation on this runner was performed with:

```sh
cargo kani setup
```

The reproducible proof gate is:

```sh
./scripts/check-kani-codec.sh
```

Its exact verifier invocation is equivalent to:

```sh
cargo kani \
  --manifest-path Cargo.toml \
  --package activechain-canonical-codec \
  --lib \
  --target-dir "${TMPDIR:-/tmp}/activechain-kani-codec" \
  --jobs 2 \
  --output-format terse \
  --default-unwind 16 \
  -Z unstable-options \
  --harness-timeout 120s
```

The runner requires the exact cargo-kani version, keeps unwinding checks enabled, applies a
120-second bound to each harness, and applies a 600-second bound to the whole Kani process group.
Those resource bounds may be overridden through the `ACTIVECHAIN_KANI_HARNESS_TIMEOUT`,
`ACTIVECHAIN_KANI_PROCESS_TIMEOUT`, `ACTIVECHAIN_KANI_JOBS`, and `ACTIVECHAIN_KANI_TARGET_DIR`
environment variables. Overriding a timeout changes runner resources, not the proof state space.

## Proven bounded properties

The proof type has an exact two-byte body: one arbitrary `u8` and one arbitrary Boolean. Its
canonical envelope has a fixed seven-byte encoding: two-byte type tag, two-byte schema version,
one-byte minimal body length, and the two-byte body.

Kani verifies seven harnesses:

1. Every value in the fixed proof type's state space survives strict envelope encode/decode and
   produces exactly seven bytes.
2. Every possible truncation of every valid proof-type envelope is rejected.
3. Appending any possible single byte to every valid proof-type envelope is rejected with exactly
   one byte of trailing data.
4. Every byte string of every length from zero through nine is safe to pass to strict decoding; if
   decoding succeeds, re-encoding produces byte-for-byte identical input. This simultaneously
   covers wrong tags, wrong versions, malformed or mismatched body lengths, invalid Boolean bytes,
   body truncation, and outer or inner trailing bytes in that bounded input space.
5. Every zero-through-six-byte input to `Decoder::read_length`, for every maximum from zero through
   sixteen, is memory-safe and any successful result is within its maximum. This covers truncated,
   non-minimal, and overflowing five-byte ULEB128 paths within the finite input bound.
6. `Decoder::read_raw` is memory-safe for every `usize` requested length against every prefix of an
   eight-byte input. Success consumes exactly the request; an overlong request returns
   `UnexpectedEnd` without advancing or indexing past the input.
7. Two bounded symbolic appends to `Encoder` are memory-safe and the resulting buffer never exceeds
   its symbolic zero-through-eight-byte output limit.

Kani's default memory-safety, undefined-behavior, assertion, arithmetic-overflow, and unwinding
checks remain enabled. The 16-iteration default unwind is sufficient for all reachable loops in
these harnesses; an insufficient bound would fail an unwinding assertion rather than silently
produce a proof.

The passing run reported:

```text
Manual Harness Summary:
Complete - 7 successfully verified harnesses, 0 failures, 7 total.
```

## Deliberate limitations

This is bounded model checking, not an unbounded proof of the codec or all protocol schemas.

- The arbitrary strict-decode input is at most nine bytes and the proof type body is exactly two
  bytes. Larger envelopes and all production `CanonicalType` implementations still require tests,
  vectors, refinement work, and further harnesses.
- The length-prefix harness bounds its input to six bytes and its schema maximum to sixteen. It
  reaches every structural ULEB128 branch, but does not quantify over arbitrary enclosing schemas.
- The encoder harness uses at most two four-byte writes and an eight-byte limit. It does not prove
  unbounded allocation behavior.
- Kani models successful allocation by default; out-of-memory behavior, resource exhaustion, and
  denial-of-service limits are outside this proof.
- This slice establishes local codec safety and strictness only. It does not establish consensus,
  cryptographic, state-machine, or cross-implementation correctness.
- The recorded proof run used Kani's native Apple Silicon bundle on macOS. Kani release bundles are
  platform-specific; another local runner must install the 0.67.0 bundle for its own host and may
  report different verification times.
- Kani emits a compile-time warning that `caller_location` and foreign-function constructs exist in
  the compiled dependency graph. Kani fails a harness if an unsupported construct is
  reachable; all seven harnesses completed successfully, so none blocked these bounded proofs.

Claims derived from this artifact must retain the words **bounded**, **two-byte proof body**, and
**inputs up to nine bytes**. It must not be described as complete or unbounded codec verification.
