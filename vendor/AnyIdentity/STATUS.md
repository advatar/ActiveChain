# AnyIdentity status

## Delivered reference milestone — 2026-09-09

- [x] Implement Rust cryptography, signed identity evidence, assurance policies, authority continuity, pairwise keys, delegation and action verification.
- [x] Expose a versioned C FFI with explicit ownership and a typed Swift API.
- [x] Add locked build scripts, an executable example, security documentation and Rust/Swift tests.
- [x] Investigate supplied patent citations and adjacent patent/non-patent prior art; deliver preliminary jurisdiction-aware FTO/patentability research with implementation mapping.
- [x] Validate Rust, Swift, universal Apple artifacts and generic iOS builds; record tests and limitations in Documentation/VALIDATION.md.

## External delivery dependency

- GitHub issue and remote push await a destination repository. The directory initially had no Git repository/remote. Issue text is prepared in Documentation/TRACKING_ISSUE.md. Implementation work is committed locally; original briefs remain untouched.

## Production/research boundaries beyond the reference core

Native government credential verification; cryptographic same-person convergence; anonymous inherited identity assurance; hardware-backed signing; durable/distributed replay and status services; fork resolution and pairwise continuity after master-secret loss; independent security review; official patent-family/legal-status clearance. These are not represented as implemented features or completed legal work. See Documentation/PROTOCOL.md and Documentation/FTO_AND_PATENTS.md.

## ActiveChain integration documentation — 2026-09-09

- [x] Document the actual sibling ActiveChain app and standalone package dependency paths.
- [x] Provide a typed canonical-proposal approval example and explain native authority, custody, time, amount and persistence boundaries.
- [x] Compile the README example against both local packages, review the diff and commit/merge locally.

The existing missing-remote delivery dependency also applies to this documentation task.

Validation: extracted the README Swift helper into a temporary Swift 6 executable consuming the actual local AnyIdentity and ActiveChainWallet packages; `swift run` compiled, linked and launched successfully on macOS. Both documented relative dependency paths and local documentation links resolve. No ActiveChain files were changed; dual-native-library app linking and end-to-end identity integration are explicitly left as consumer integration checks.

## Tanzanian digital identity research — 2026-09-09

- [x] Verify official NIDA integration routes, onboarding requirements and alternatives.
- [x] Assess data-handling requirements and map verified capabilities to AnyIdentity/ActiveChain.
- [x] Deliver a cited research note with a recommended architecture, unresolved access questions and implementation milestones; link it from README and validate the documentation.

Research only: do not enroll institutions, submit personal data or contact providers. Issue publication/push remains dependent on an AnyIdentity remote; track the task in Documentation/TRACKING_ISSUE.md.

Delivered: Documentation/TANZANIA_IDENTITY.md compares direct NIDA and provider routes, distinguishes Jamii programme descriptions from established integration specifications, and maps a proposed backend attestor to current code. Local documentation links/fences and `git diff --check` passed; `swift build` passed on macOS. No implementation or live upstream verification was performed. Operating-entity eligibility, current private API specifications, pricing, data-processing arrangements and live access remain discovery dependencies for a future integration, not unfinished research tasks.
