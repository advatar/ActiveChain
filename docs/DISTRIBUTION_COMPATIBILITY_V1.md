# Distribution and compatibility metadata v1

Every wallet/verifier release publishes a machine-readable compatibility manifest alongside its
artifact. The manifest includes chain ID/genesis, protocol and verifier revisions, canonical ABI
revision, schema/vector set, supported proof kinds, minimum OS/toolchain, artifact digest, and
build provenance.

Apple distribution uses reproducible XCFramework or SwiftPM binary-target artifacts. Generated
headers and Swift module interfaces are committed to the release manifest; local stubs are marked
development-only and cannot satisfy a production artifact check.

Compatibility is explicit: a client accepts only supported protocol/schema revisions and known
future-extension rules. Upgrade policy names migration windows, rollback/halting behavior, and
whether persisted state can be opened. Unknown revisions fail closed with a typed incompatibility
result rather than silently decoding old bytes under new semantics.
