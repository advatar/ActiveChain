# Amber native application

Amber is ActiveChain's private imageboard client. The same SwiftUI source set builds native iOS and
macOS applications. Emerald is a research benchmark, not the product name or an interoperability
claim.

The current application renders bounded deterministic sample content while content retrieval remains
under development. Its network strip performs a real TLS-framed ActiveChain status request against
the configured Kanalen endpoint on launch and on demand. It distinguishes verified, stale, degraded,
unavailable, and protocol-incompatible network states. State proofs, content shards, and privacy
transport are not yet connected.

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
catalog, primary iPhone/iPad icon metadata, and the required 152×152 iPad rendition.

The default endpoint is `https://rpc.kanalen.activechain.dev`. The status client validates canonical
framing, the response envelope, protocol and schema revisions, finalized height, proof identifiers,
and health/staleness consistency. A later network-integration change will persist operator/user
overrides and pin the expected chain identity and genesis commitment.
