# ActiveChain audit scope and acceptance checklist

This document is the auditor hand-off for the developmental protocol. It answers exactly what
must be reviewed, what evidence must be produced, and what cannot be treated as audit evidence.
The audit commit must be frozen before review; findings apply to that commit and its published
specification set.

## Release boundary

The audit covers any code that can accept, authorize, commit, prove, persist, or display a state
transition. A green test, formal model, or internal review is evidence for the auditor, never a
substitute for independent review. Until the final report and re-review are published, all wallets,
verifiers, faucet services, and testnets remain developmental.

## Required workstreams

| Workstream | Code/specification boundary | Auditor must establish |
|---|---|---|
| Consensus and finality | `crates/consensus-runtime`, `consensus-verifier`, `finality-types`, `data-availability`, P-020/P-133 | authenticated peer sessions, proposal/vote/certificate safety, replay and equivocation rejection, quorum and view-change safety, restart and partition recovery, deterministic finality |
| Cash and economics | `crates/cash-kernel`, `cash-air`, `cash-state`, `transition`, `state-tree`, `CASH.md`, `MINT.md`, P-060/P-130/P-132 | no double spend/mint/burn, supply and fee conservation, owner/asset binding, range soundness, proof soundness assumptions, bounded proof costs, issuance and reward invariants |
| Canonical encoding | `crates/canonical-codec`, `protocol-types`, `schema/activechain.idl` | injectivity, length bounds before allocation, unknown-tag/version rejection, trailing-byte rejection, deterministic ordering, no parser differentials |
| Authorization and execution | `principal`, `credential`, `capability`, `policy-kernel`, `bytecode-verifier`, `object-vm`, P-000/P-050/P-121 | default denial, capability attenuation, nonce/replay safety, gas/resource bounds, deterministic interpreter/verifier agreement, atomic failure behavior |
| PQ cryptography | `crypto-provider`, `protocol-commitment`, `principal`, `credential`, P-095/P-111 and migration policy | approved parameter sets and encodings, domain separation, randomness, key rotation/recovery/revocation, downgrade resistance, side-channel and misuse boundaries |
| Wallet and native ABI | `wallet-core`, `wallet-ffi`, `verifier-ffi`, `mobile/ios`, `mobile/android`, `docs/mobile-wallet.md` | pointer/length/lifetime safety, panic/unwind behavior, secret zeroization, secure storage attributes, signing-intent/UI equivalence, backup/recovery and fail-closed behavior |
| Identity and compliance | `application-primitives`, `compliance`, `credential`, EUDI/OpenID adapters, P-095/P-120/P-121 | selective disclosure, audience/nonce binding, freshness and status, sanctions/KYC policy composition, provenance and assurance-class non-escalation, no global-KYC bypass |
| RPC, faucet, and deployment | `rpc-server`, `rpc-types`, `validator-rpc-bridge`, faucet code, owner-state APIs | finalized-only responses, chain/genesis binding, pagination bounds, authentication, exactly-once funding, replay/concurrency/exhaustion behavior, no optimistic wallet balances |
| dBrowser and content | dBrowser RPC/verifier contracts, Amber integration, browser-facing schemas | verified-finality gating, content provenance, bonded submission authorization, bounded parsing, no unfinalized or unauthorized publication |
| Threat model and operations | ingress, networking, DA, validator tooling, scripts, CI, observability | DoS/resource exhaustion, eclipse/partition, malformed input, fee manipulation, verifier-duty gaming, key compromise, incident recovery and reproducible builds |

## Evidence package requested

Auditors receive the frozen commit, toolchain lockfiles, normative specs, threat model, vector
manifest, malformed/tampered vectors, fuzzing corpus and coverage, benchmark data, formal proof
inventory, dependency/SBOM report, reproducible-build instructions, deployment manifests, and
the complete CI results. The Go independent-client M2 output must include its command transcript
and the 218-case result; it is a conformance input, not a replacement for a full independent
transition implementation.

## Finding and re-review rules

Every finding must name an affected commit/spec, severity (critical/high/medium/low), security
property, reproduction or proof obligation, affected assets, and remediation recommendation.
Critical/high findings block a non-developmental release. Medium findings require a fix or signed
risk acceptance; low findings require disposition. The auditor must re-review every remediation,
rerun affected vectors/tests, and confirm that the final report matches the released commit.

## Explicit exclusions

Marketing graphics, experimental branches, archived local work, ignored benchmark timing, and
future protocol features not reachable from the frozen release are excluded. Their exclusion must
be listed in the final report; exclusion does not permit code paths reachable by a release build to
be omitted.

## Completion criteria

The audit gate is complete only when an independent firm is engaged, the frozen commit is reviewed,
all findings have disposition, fixes have passed re-review, and the final report plus remediation
log are published. Until then, release claims remain developmental.
