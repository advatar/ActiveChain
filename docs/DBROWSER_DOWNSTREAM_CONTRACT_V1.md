# dBrowser downstream contract v1

dBrowser integrates through stable versioned boundaries rather than internal ActiveChain crates.

## Verifier SDK

The SDK must expose chain identity/genesis validation, finality verification, canonical envelope
decoding, state/action/receipt proof verification, and explicit unsupported-proof errors. It must
ship positive and malformed vectors and report verifier/protocol revisions.

## Wallet ABI

The wallet boundary exposes profile/asset discovery, policy evaluation, canonical intent creation,
approval-bound signing, secure key callbacks, and transaction submission. A local stub may be used
only in development and must report `artifact_not_linked` rather than pretending to verify live
state.

## RPC and light client

The query contract includes chain identity, genesis, protocol revision, finalized height,
staleness/health, supported proofs, and proof-bearing state/action/receipt queries. A light client
must verify checkpoints and validator transitions before accepting state.

No production readiness, independent audit, or native Apple artifact claim is made until signed
reproducible artifacts and the external engagement gates are complete.
