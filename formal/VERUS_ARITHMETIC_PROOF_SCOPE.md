# Verus arithmetic proof scope

## Result

`formal/verus/activechain_arithmetic.rs` is an executable Verus target for the checked arithmetic at
the native-money, fee-market, and weighted-quorum boundaries. The pinned runner verifies eight
functions with zero errors under `--no-cheating`, compiles the verified target, executes it, and then
executes a Rust parity program against the production crates.

The target proves, for all values admitted by each function's contract:

1. `FeeQuote::total`-shaped resource multiplication and fee addition return a value exactly when the
   non-negative mathematical total fits in `u128`; otherwise they return `None`.
2. For nonzero total stake and signer stake no greater than total stake, the checked production
   threshold accepts exactly when the division-free inequality
   `3 * signer_stake > 2 * total_stake` holds over mathematical integers. Either multiplication
   overflowing `u128` is reported as `None`, never wrapped.
3. `FeeMarket::next`-shaped adjustment checks the basis-point multiplication, checks the increasing
   addition, preserves the exact floor division by 10,000, and keeps a decreasing fee at least one.
4. The epoch supply equation checks both `pre_supply + issuance` and subtraction of the burn before
   producing `pre_supply + issuance - burn`.
5. The circulating, vesting, staked, and reserve partition sum is exact or reports overflow.
6. Security-fee plus reserve coverage is checked, the target-budget gap is saturating, and issuance
   above the cap is rejected. Any successful issuance is at most the target budget.

No project proof contains `assume`, `admit`, `external_body`, or an assumed specification. The runner
uses Verus's `--no-cheating` gate so those proof shortcuts fail verification. As with any Verus proof,
the trusted base still includes the Verus compiler, Z3, the pinned `vstd` package (including its Rust
primitive specifications), the Rust compiler used for the compiled target, and the operating system.

## Reproducible toolchain

`formal/verus/verify.sh` pins official Verus release `0.2026.05.24.ecee80a`, source commit
`ecee80a2139923d503338e6989f79fb690ec7847`. It supports the local Apple-silicon runner directly and
also records the official x86-64 Linux artifact:

| Platform | Official release asset | SHA-256 published by GitHub Releases |
| --- | --- | --- |
| macOS arm64 | `verus-0.2026.05.24.ecee80a-arm64-macos.zip` | `792f4b4d616aeee0cdef9804f8b0ecf03012a305c9cf7626c406b32b9a0713ac` |
| Linux x86-64 | `verus-0.2026.05.24.ecee80a-x86-linux.zip` | `323a44c0d787ce9a788665e1c6922360c44a72d1b9696359ec4f7bf5fbbc63e6` |

The runner downloads only over TLS, checks the selected archive before extraction, checks the binary's
reported version, and keeps downloaded and generated artifacts outside the repository by default.
Run the complete slice from the repository root:

```sh
formal/verus/verify.sh
```

Set `ACTIVECHAIN_VERUS_CACHE_DIR` to use a different task-specific cache location.

## Production parity boundary

The Verus release cannot yet verify the ActiveChain workspace directly because the workspace and its
dependency graph are ordinary Rust rather than a Verus crate. The verified file is therefore a small,
executable target module that deliberately mirrors these pure production paths:

- `crates/cash-kernel/src/economics.rs`: `FeeQuote::total` and `FeeMarket::next`;
- `crates/cash-kernel/src/types.rs`: `NativeSupply::new` and
  `EpochEconomicsTransition::new`; and
- `crates/protocol-types/src/consensus.rs`: `QuorumCertificate::new`'s checked threshold.

`formal/verus/parity` is a separate, locked Rust executable. It compiles those actual production
crates and checks the same frozen success, threshold-boundary, multiplication-overflow,
addition-overflow, subtraction-underflow, partition, fee-floor, coverage-overflow, and issuance-cap
vectors asserted by the Verus target. This catches ordinary semantic drift at the pinned vectors.

The parity executable is finite differential testing, not a proof that every future production edit
refines the Verus target. Closing that refinement gap requires either moving these verified functions
behind a shared production API that Verus compiles, or adding a mechanically checked trace/refinement
bridge covering all inputs.

## Explicit exclusions

This slice does not prove:

- the cryptography, validator membership, vote-set construction, or chain-prefix consensus safety;
- that a caller is authorized to mint, burn, charge, or settle the quantities supplied to arithmetic;
- correctness of the full Cash ledger, parallel execution, fee funding, rewards, or state roots;
- arbitrary-length stake aggregation or uniqueness of validators; or
- end-to-end correspondence between all Rust implementations and these target functions.

The initial `total_stake > 0` and `signer_stake <= total_stake` guards remain production constructor
logic and parity-tested preconditions around the formally verified quorum arithmetic stage.
