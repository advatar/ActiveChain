# Implement AnyIdentity Swift/Rust authority protocol and investigate patents

Issue draft — destination repository not yet supplied. Do not create a public issue containing the invention briefs without an appropriate release decision.

## Requested work

Build a Swift package using Rust and FFI from BRIEF1.md; investigate freedom to operate and patentability from PATENT.md.

## Implementation

Provide a Rust Ed25519/HKDF/SHA-256 protocol core, C ownership-safe FFI, typed Swift 6 interface and Apple XCFramework build scripts. Support signed enrollment/evidence, trusted multi-root assurance, key rotation and guardian recovery, pairwise keys, scope-attenuated delegation, action binding, revocation and in-process replay prevention. Supply unit/integration tests and an executable synthetic-attestor example.

## Investigation

Audit brief citations, search adjacent patents and non-patent disclosures, identify granted claims and national-family leads, map claim mechanisms to actual code, and distinguish patentability from FTO. Report limitations in official-record and territorial coverage. Deliver a counsel-facing research memorandum without declaring clearance or selecting a patent/copyright licence.

## Acceptance evidence

See VALIDATION.md for actual executed checks and PROTOCOL.md for implementation boundaries. The larger production integrations and unresolved legal work are explicitly documented there and in FTO_AND_PATENTS.md.

## Follow-up: ActiveChain integration README

Document integration with the sibling `../../ActiveChain` checkout, including XcodeGen app dependencies and the standalone Swift package. Show how identity assurance gates an already canonically reviewed MCP proposal before existing native custody signing. Explain incompatible keys/commitments, height versus wall-clock expiry, native amounts, real attestors and durable replay requirements. Compile the example against both local packages and commit the documentation; publishing this issue and pushing remain blocked by the missing AnyIdentity remote.

## Follow-up: Tanzanian digital identity research

Research official NIDA verification/integration routes and credible alternatives, distinguish source verification from holder proof and key binding, assess data protection/access prerequisites, and propose an AnyIdentity attestor architecture compatible with ActiveChain's native authority. Deliver current primary-source citations, an explicit uncertainty/access list and implementation milestones. Research does not authorize provider enrollment, personal-data submission or external outreach.
