# Proof-finalized cash throughput benchmark

This tool measures the complete local cash-processing boundary for each deterministic two-transfer
batch:

1. create, ML-DSA-44 sign, and cryptographically verify each exact cash authorization;
2. execute the transfer batch and derive its authenticated Coin Cell post-state;
3. generate and verify the specialized CashAIR STARK;
4. wrap the verified trace and proof in the canonical receipt envelope; and
5. Reed-Solomon encode, serialize, deserialize, reconstruct, and byte-compare that receipt.

Run a short functional sample with:

```sh
cargo run -p activechain-cash-throughput-benchmark --offline -- 3
```

Run a measurement candidate with a fixed toolchain, idle host, and an explicitly recorded sample
count:

```sh
cargo run --release -p activechain-cash-throughput-benchmark --offline -- 100
```

The sole argument is the nonzero number of independently verified batches. Output is JSON and
includes stage timings, end-to-end verified transfers per second, proof/receipt/availability byte
sizes, shard layout, and trace bound. Fixed seeds make workload construction reproducible; timing
still depends on the host, Rust toolchain, build profile, thermal state, and background load.

The benchmark reports local proof-finalization throughput. It does not claim public-network
consensus throughput, latency, production capacity, or mainnet readiness. Such claims additionally
require the full qualification gates, multi-validator network measurements, independent review,
and a published environment manifest.
