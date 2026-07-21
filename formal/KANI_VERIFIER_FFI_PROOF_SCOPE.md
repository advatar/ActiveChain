# Verifier C ABI Kani Proof Scope

Status: bounded verification slice implemented and passing on 2026-07-21.

This slice runs Kani against the production source for `activechain-verifier-ffi` and its real
`activechain-verifier-api`, `activechain-protocol-types`, and `activechain-canonical-codec`
dependencies. The five proof harnesses call the exported `extern "C"` functions directly. They do
not use a copied pointer adapter, parser model, fake commitment function, disabled safety check, or
placeholder assertion.

## Pinned verifier and source preflight

- `cargo-kani 0.67.0`
- Kani driver `0.67.0`
- Kani release bundle `kani-0.67.0-aarch64-apple-darwin`
- bundled CBMC `6.8.0`
- bundled Rust `nightly-2025-11-21-aarch64-apple-darwin`
- bundled `rustc 1.93.0-nightly (53732d5e0 2025-11-20)`

Kani 0.67.0 cannot load the main workspace's Rust 1.97.1 package metadata. The verification-only
workspace under `crates/verifier-ffi/kani-workspace` therefore declares Rust 1.93 package metadata
while each library target points to the production source file. Before every proof run, the runner
uses Cargo metadata and real-path comparison to reject a target that does not resolve to one of
these exact files:

- `crates/canonical-codec/src/lib.rs`
- `crates/protocol-types/src/lib.rs`
- `crates/verifier-api/src/lib.rs`
- `crates/verifier-ffi/src/lib.rs`

The preflight also requires the proof workspace lock's external package versions, sources, and
checksums to occur in the production `Cargo.lock`. The shim changes package metadata only; it is not
an alternate verifier implementation.

Run the reproducible gate with:

```sh
./scripts/check-kani-verifier-ffi.sh
```

After the source and lock preflight, its verifier invocation is equivalent to:

```sh
cargo kani \
  --manifest-path crates/verifier-ffi/kani-workspace/Cargo.toml \
  --package activechain-verifier-ffi \
  --lib \
  --target-dir "${TMPDIR:-/tmp}/activechain-kani-verifier-ffi" \
  --jobs 2 \
  --output-format terse \
  --default-unwind 80 \
  -Z unstable-options \
  --harness-timeout 180s
```

Default memory-safety, undefined-behavior, arithmetic-overflow, assertion, and unwinding checks stay
enabled. The runner applies a 600-second process-group timeout and runs Cargo offline after the
locked preflight. Resource bounds can be changed with the `ACTIVECHAIN_KANI_FFI_PROCESS_TIMEOUT`,
`ACTIVECHAIN_KANI_FFI_HARNESS_TIMEOUT`, `ACTIVECHAIN_KANI_FFI_JOBS`, and
`ACTIVECHAIN_KANI_FFI_TARGET_DIR` environment variables. Changing a timeout does not change the
verified state space.

## Mechanically checked properties

Kani reported:

```text
Manual Harness Summary:
Complete - 5 successfully verified harnesses, 0 failures, 5 total.
```

The harnesses establish these bounded production-code properties:

1. For every non-zero `u32` envelope length and every expected type/version pair, a null envelope
   pointer returns stable code `6` without constructing a Rust slice.
2. For every `u32` envelope length above 262,144 bytes and every expected type/version pair, a
   non-null dangling pointer returns stable code `1` before pointer materialization. This is also a
   regression proof for the production change that moved the published envelope bound ahead of
   `slice::from_raw_parts`.
3. For every byte string up to nine bytes, every prefix length from zero through nine, and every
   expected type/version pair, a pointer to a real nine-byte allocation returns exactly the same
   status as `activechain_verifier_api::inspect_envelope_code`. The wrapper does not modify that
   caller allocation.
4. The fixed canonical envelope `1234 0001 01 aa` succeeds with code `0`; every proper truncation
   fails with code `2`; a wrong type fails with code `3`; a wrong version fails with code `4`; and
   one trailing byte fails with code `2`.
5. For every non-zero `u32` declared length, a null domain pointer or null body pointer at that
   length returns code `6`, and a null fixed 48-byte digest pointer returns code `6`. These paths
   return before constructing a slice or invoking SHAKE256.

Kani warns that `caller_location` and a foreign-function construct exist somewhere in the compiled
dependency graph. Kani fails a harness if an unsupported construct is reachable. All five harnesses
completed successfully, so neither construct blocks the verified paths. The same-crate exported
`extern "C"` wrappers themselves are the harness entry paths and are mechanically checked here.

## Ordinary commitment regression tests, not Kani claims

The production unit tests call `activechain_verify_commitment_code` with the published SHAKE256/384
empty-input vector, require code `0`, flip one digest bit, and require code `5`. They also retain the
null-digest regression.

Expanding the complete SHAKE256 implementation inside Kani required an unwind bound above the
136-byte Keccak rate and exceeded a conservative 240-second per-harness run. Those two cryptographic
paths are deliberately not marked as Kani proofs. No unwinding assertion, overflow check, memory
check, or unsupported-function check was disabled to manufacture a passing result. The stable
commitment mismatch code is covered by executable production tests and remains a future
compositional or higher-capacity model-checking target.

## Deliberate limitations

This is bounded C ABI refinement, not proof that arbitrary foreign memory is valid.

- A foreign caller must still ensure that every accepted non-null address identifies a readable
  allocation of the declared in-bound length. Kani can prove behavior for Rust-owned allocations
  and prove that null or oversized cases return before dereference; it cannot quantify over memory
  owned by Swift, Kotlin, JavaScript, or C.
- The arbitrary envelope allocation is at most nine bytes. Larger in-bound buffers rely on the same
  wrapper shape, production tests, malformed vectors, fuzzing, sanitizers, and native-binding
  review.
- The current ABI has no output buffer: both exported functions accept only `const` input pointers
  and return a numeric status. Consequently there is no output capacity, partial-write, or required
  output-length property to prove in this revision. P-110's future caller-owned canonical-body and
  structured-detail output interface remains open and must receive its own bounds and proofs when
  introduced.
- Kani does not establish that a foreign caller used the header's correct integer widths or calling
  convention, and it does not replace C/Swift/Kotlin ABI integration tests or sanitizers.
- The proof does not establish SHAKE256 collision resistance, cryptographic correctness, schema
  semantics, consensus finality, light-client trust, denial-of-service resistance, or whole-system
  security.

Claims derived from this artifact must retain the words **bounded**, **inputs up to nine bytes**,
and **foreign readable-memory precondition**. It must not be described as complete FFI, output
buffer, or cryptographic verification.
