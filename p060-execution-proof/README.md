# P-060 execution proof reference

This package contains the P-060 v0.2 specification and a running Gate-1 Option-A reference implementation. It generates and verifies real transparent STARK proofs with a strictly encoded, protocol-bound receipt.

It is intentionally honest about scope: the AIR proves a small accumulator state machine because P-050 ObjectVM semantics were not provided. The receipt, suite registry, security parameters, verifier controls, vectors, and measurement workflow are implemented; P-050 refinement and an independent verifier remain activation blockers.

## Quick start

Rust 1.87 or newer is required. Dependencies are pinned by `Cargo.lock`.

```sh
cargo test
cargo build --release

# Pre-state 5; add 7, multiply by 9, add 11; output receipt.bin
target/release/p060 prove 5 add:7,mul:9,add:11 receipt.bin
target/release/p060 verify receipt.bin
target/release/p060 inspect receipt.bin

# Regenerate the deterministic published vector
target/release/p060 vector vectors

# Benchmark 1,024 actions and verify the receipt ten times
target/release/p060 bench 1024 10
```

Use `-` as the operation list for an empty block.

## Package map

- `P-060.md` — normative specification and implementation status.
- `src/air.rs` — accumulator AIR and public-element binding.
- `src/hash.rs` — domain-separated SHAKE256/384 suite hasher.
- `src/codec.rs` — bounded canonical receipt decoder and encoder.
- `src/verifier.rs` — exact-suite verifier contract.
- `src/prover.rs` — trace construction and transparent prover.
- `src/model.rs` — canonical block and stand-in transition model.
- `tests/protocol.rs` — end-to-end, mutation, determinism, and totality tests.
- `vectors/` — deterministic positive and malformed receipt vectors.
- `BENCHMARKS.json` — recorded Gate-1 measurements.

## Security status

The registered suite reports 127-bit conjectured security, but only 53–82 bits under Winterfell’s proven estimators for the measured traces. It has not been independently audited and is not consensus-ready. See §§5, 10, 13, and 15 of the specification before relying on it.
