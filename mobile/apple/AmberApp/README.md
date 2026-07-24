# Amber native application

Amber is ActiveChain's private imageboard client. The same SwiftUI source set builds native iOS and
macOS applications. Emerald is a research benchmark, not the product name or an interoperability
claim.

The current application is an honest offline product shell. It renders bounded deterministic sample
state and displays the configured Kanalen testnet RPC endpoint, but it does not yet claim that RPC
identity, state proofs, content shards, or privacy transport are connected.

The composer presents posting as a bonded action, never a free action. Its testnet preview quote
separates the spent posting fee, locked refundable post bond, and maximum moderation slash. The
submit control intentionally fails closed until a verified wallet escrow and RPC submission path
replace the preview values. Emergency hiding does not by itself finalize an economic penalty.

Generate the Xcode project and run all tests and builds:

```text
scripts/test-amber-app.sh
```

The script runs the shared unit suite through the native macOS target and an iPhone Simulator,
thereby compiling both application targets. Override the simulator when needed with
`AMBER_IOS_TEST_DESTINATION`.

For release qualification, run
`scripts/validate-apple-app-icon.sh /path/to/Amber.app`. The validator requires a compiled asset
catalog and `CFBundleIcons.CFBundlePrimaryIcon.CFBundleIconName = AppIcon`.

The default endpoint is `https://rpc.kanalen.activechain.dev`. A later network-integration change
will persist operator/user overrides and will only mark an endpoint verified after checking its
chain identity, genesis commitment, protocol revision, finalized height, proof support, and
health/staleness response.
