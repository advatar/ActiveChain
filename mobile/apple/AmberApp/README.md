# Amber native application

Amber is ActiveChain's private imageboard client. The same SwiftUI source set builds native iOS and
macOS applications. Emerald is a research benchmark, not the product name or an interoperability
claim.

The current application is an honest offline product shell. It renders bounded deterministic sample
state and displays the configured Kanalen testnet RPC endpoint, but it does not yet claim that RPC
identity, state proofs, content shards, or privacy transport are connected.

Generate the Xcode project and run all tests and builds:

```text
scripts/test-amber-app.sh
```

The script runs the shared unit suite through the native macOS target and an iPhone Simulator,
thereby compiling both application targets. Override the simulator when needed with
`AMBER_IOS_TEST_DESTINATION`.

The default endpoint is `https://rpc.kanalen.activechain.dev`. A later network-integration change
will persist operator/user overrides and will only mark an endpoint verified after checking its
chain identity, genesis commitment, protocol revision, finalized height, proof support, and
health/staleness response.
