# ActiveChain independent auditor assurance protocol

> **Document status:** Draft v0.1 for public review  
> **Prepared:** 2026-07-24  
> **Intended repository path:** `docs/audits/AUDITOR_ASSURANCE_PROTOCOL.md`  
> **Repository:** [advatar/ActiveChain](https://github.com/advatar/ActiveChain)  
> **Project status:** Developmental. This document is an audit protocol, not an audit report or a statement that an audit has been completed.

## 1. Purpose

This protocol defines how an independent auditor assesses ActiveChain and any ActiveChain-based operator, wallet, bridge, payment service, or asset issuer. It is designed to produce evidence that can be inspected by technical reviewers, financial-crime specialists, counterparties, and competent authorities.

The protocol covers:

1. ledger integrity and fraud resistance;
2. authorization, identity, credentials, custody, and privacy;
3. anti-money-laundering, counter-terrorist-financing, counter-proliferation-financing, sanctions, and fraud controls;
4. Travel Rule and self-hosted-address controls where a regulated intermediary is involved;
5. issuer, reserve, redemption, bridge, and payment-connector controls;
6. software supply chain, formal methods, operational resilience, and incident response; and
7. the quality, provenance, publication, and re-performance of audit evidence.

This protocol complements, and does not replace, the existing [ActiveChain pre-launch security-audit scope](../SECURITY_AUDIT.md).

## 2. Claims this protocol does and does not permit

A public blockchain, source-code repository, cryptographic credential, policy engine, or completed security audit does **not** by itself establish legal or regulatory compliance. Legal obligations attach to facts such as the activities performed, control exercised, customers served, assets issued, custody provided, and jurisdictions involved.

An audit report produced under this protocol MUST therefore identify the exact audited role, module, jurisdiction, deployment, configuration, commit, and observation period. It MUST NOT make an unqualified statement such as “ActiveChain is AML compliant.” Permitted conclusions are narrower, for example:

> “The named hosted-wallet operator's specified EU regulated-transfer profile was designed and operated effectively for the stated period, subject to the listed limitations, at the frozen code and configuration revisions.”

The following boundaries are mandatory:

- A chain principal or wallet address is not automatically a verified natural person, legal person, customer, or beneficial owner.
- A credential proves only what its authorized issuer, schema, holder binding, status, freshness, and verification procedure justify.
- Consensus can verify canonical evidence and enforce policy. It cannot determine whether an identity document is genuine, whether a screening provider is complete, whether conduct is suspicious, or whether a suspicious-transaction report should be filed without accountable off-chain controls.
- Permissionless peer-to-peer transfers and regulated hosted services are different assurance objects. KYC or sanctions controls required for a CASP, issuer, hosted wallet, or payment operator MUST be scoped to that activity and MUST NOT be represented as universal base-layer identity.
- Raw KYC records, official-document numbers, addresses, dates of birth, Travel Rule payloads, sanctions-match details, case notes, and suspicious-transaction reports MUST NOT be published on-chain or in the public repository. The public chain may carry minimal commitments, status references, policy versions, and non-sensitive audit receipts.
- The existence, contents, filing decision, or subject of a suspicious-transaction report MUST remain confidential and subject to applicable anti-tipping-off rules.

## 3. Normative language and terminology

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** describe requirements of this assurance protocol. They do not purport to restate every legal obligation in every jurisdiction.

| Term | Meaning in this document |
| --- | --- |
| **Audit subject** | The exact code, deployment, organization, service, asset, or control environment under examination. |
| **Control owner** | The accountable legal or natural person responsible for operating a control. |
| **Regulated profile** | A versioned policy and operating configuration intended for a specific regulated activity and jurisdiction. |
| **CASP/VASP** | A crypto-asset or virtual-asset service provider as defined by the applicable legal framework. |
| **CDD/KYC/KYB** | Customer due diligence for individuals and legal persons, including beneficial ownership where applicable. |
| **AML/CFT/CPF** | Anti-money-laundering, counter-terrorist-financing, and counter-proliferation-financing. |
| **Travel Rule evidence** | Originator/beneficiary information and related acknowledgements transmitted securely outside the public ledger and bound to the exact transfer. |
| **Design effectiveness** | Whether a control, if operated as designed, would address its stated risk. |
| **Operating effectiveness** | Whether the control actually operated consistently during the stated observation period. |
| **Evidence commitment** | A cryptographic commitment to evidence retained in an authorized confidential system. It is not the evidence itself. |

## 4. Assurance modules

The auditor MUST report each module separately. A module not examined MUST be marked **Not examined**, not silently omitted.

| Module | Audit object | Principal assertion |
| --- | --- | --- |
| **CORE** | Consensus, canonical encoding, state transition, cash, finality, authority, cryptography | Unauthorized state changes, value creation, double spending, replay, and evidence substitution are prevented within the frozen scope and stated assumptions. |
| **IDENTITY** | Principals, credentials, capabilities, policies, wallets, key lifecycle | Authentication and delegated authority are bounded; verified identity evidence is provenance-aware, status-aware, privacy-preserving, and not overstated. |
| **REGULATED-TRANSFER** | Hosted wallet, CASP gateway, payment operator, regulated application profile | Required CDD, sanctions, Travel Rule, self-hosted-address, monitoring, and escalation controls are enforced before or around the relevant service action. |
| **FINANCIAL-CRIME-OPS** | Compliance organization and operating systems | Risk assessment, ongoing monitoring, case investigation, reporting, recordkeeping, training, and independent testing operate effectively. |
| **ASSET-ISSUER** | Fungible asset, stablecoin, tokenized instrument, issuer and reserve arrangements | Issuance, redemption, burn, reserves, governance, disclosures, and exceptional controls are authorized, reconciled, and independently evidenced. |
| **BRIDGE-PAYMENT** | Bridge, payment connector, external settlement provider, oracle | External observations cannot be upgraded into stronger assurance; mint/burn/lock/unlock and payment state are idempotent, reconciled, and fail safely. |
| **WALLET-CUSTODY** | Mobile, desktop, hardware, institutional, or hosted custody | Secret material, approvals, recovery, backups, signing intent, and privileged actions are protected and independently tested. |
| **OPERATIONS** | Validators, RPC, deployment, incident response, business continuity, third parties | Production configuration matches the audited release and operational failures, attacks, fraud events, and regulatory requests are managed and evidenced. |

### 4.1 Assurance stages

| Stage | Meaning | Minimum basis |
| --- | --- | --- |
| **S0 — Documentation only** | Assertions and designs were read. No implementation assurance. | Public and confidential documentation. |
| **S1 — Design and implementation** | Controls were traced from requirements to implementation and configuration. | Frozen source/configuration, walkthroughs, code review, evidence mapping. |
| **S2 — Independently tested** | The auditor reproduced builds, tests, negative cases, and deployment checks on auditor-controlled infrastructure. | S1 plus independent test evidence. |
| **S3 — Operating effectiveness** | Organizational and automated controls operated over a stated period. | S2 plus representative and risk-based operating samples. |

A production compliance opinion for a CASP, issuer, or hosted-wallet activity SHOULD be **S3**. A code audit without an operating period MUST NOT be presented as an operating-effectiveness conclusion.

## 5. Auditor independence and competence

The auditor MUST:

- be independent of the code authors, operators, issuers, investors, and vendors whose work is being assessed;
- disclose financial interests, prior implementation work, referral arrangements, and other conflicts;
- control its own test methodology, sample selection, infrastructure, and findings;
- have demonstrable competence in Rust ledger systems, cryptography, wallet/custody security, and the relevant operational and regulatory domains;
- include AML/CFT, sanctions, fraud, privacy, and legal-regulatory specialists whenever the corresponding modules are in scope;
- report unresolved scope restrictions and management interference; and
- retain sufficient work papers for re-performance by a competent reviewer.

Internal review, CI results, formal models, provider attestations, and management representations are audit inputs. They are not substitutes for independent testing.

## 6. Pre-engagement role and jurisdiction determination

Before testing starts, the sponsor and auditor MUST complete a role-and-jurisdiction matrix. Classification is based on activities and actual control, not product labels.

| Question | Required answer and evidence |
| --- | --- |
| Who develops and can change the protocol, clients, hosted interfaces, policy registries, and production configuration? | Named legal persons, governance instruments, access lists, change logs, and emergency powers. |
| Who operates validators, RPC, indexers, relays, hosted wallets, matching, exchange, transfer, custody, bridge, payment, or issuer services? | Entity, jurisdiction, service description, contracts, licence/registration position, and responsible control owner. |
| Who issues, redeems, freezes, burns, or markets each asset? | Issuer/controller identities, legal terms, asset classification, authority limits, reserve arrangements, and disclosures. |
| Who has customers or business relationships? | Customer journey, contractual counterparty, onboarding entity, data controller/processor roles, and complaint path. |
| Which jurisdictions are served or excluded? | Country-by-country analysis covering establishment, solicitation, customer location, asset location, and cross-border activity. |
| Is any natural or legal person able to exercise control or sufficient influence over a purportedly decentralized service? | Governance keys, upgrade rights, fees, front-end control, parameter control, treasury, branding, and practical influence. |
| Which FIU, sanctions regimes, privacy authorities, and supervisory bodies are relevant? | Versioned legal register with named owner and review date. |

The auditor MUST obtain a legal memorandum from qualified counsel for every production regulated profile. The auditor MAY rely on it for legal classification but MUST test whether the factual assumptions in that memorandum match reality.

## 7. Audit freeze and evidence chain of custody

### 7.1 Frozen audit object

The engagement record MUST include:

```text
audit_id
audit_subject_name
legal_entity_and_role
jurisdictions
repository_url
full_40_character_git_commit
signed_release_tag
source_archive_sha256
submodule_commits
Cargo.lock_sha256
rust_toolchain
Lean_Tamarin_Kani_Verus_versions
container_image_digests
SBOM_sha256
build_environment_description
release_binary_hashes
mobile_application_hashes_and_store_versions
chain_id_and_genesis_hash
validator_and_RPC_configuration_hashes
policy_profile_ids_and_revisions
credential_schema_and_issuer_registry_revisions
sanctions_and_risk_data_provider_versions
Travel_Rule_message_profile_version
observation_period_start_and_end
```

Links to `main` are navigation aids only. Public audit evidence MUST use GitHub permalinks containing the frozen full commit SHA.

### 7.2 Evidence grades

| Grade | Evidence | Treatment |
| --- | --- | --- |
| **E0** | Marketing statement, unchecked assertion, screenshot without provenance | Insufficient by itself. |
| **E1** | Versioned specification, policy, architecture, or procedure | Supports design intent only. |
| **E2** | Automated test, deterministic vector, signed system log, configuration export | Supports implementation or operation when provenance is verified. |
| **E3** | Formal model/proof or production-code harness plus explicit assumptions and conformance evidence | Supports only the stated theorem/harness scope. |
| **E4** | Auditor-reproduced build/test on auditor-controlled infrastructure | Strong independent technical evidence. |
| **E5** | Operating-period population, sampled cases, independent confirmations, reconciliations, and control-owner records | Required for operating-effectiveness conclusions. |

### 7.3 Evidence rules

Every evidence item MUST have an ID, owner, source, creation time, collection time, immutable hash, confidentiality class, associated controls/tests, result, limitations, and retention location. Screenshots SHOULD be corroborated by exports or direct read-only access. Management-generated spreadsheets MUST be reconciled to source systems and checked for completeness.

Public evidence MUST exclude secrets, personal data, KYC documents, Travel Rule payloads, sanctions-match details, suspicious-activity information, exploitable unpatched details, and information restricted by law. A public manifest MAY contain a salted or otherwise non-enumerable commitment to confidential evidence; low-entropy facts MUST NOT be exposed through guessable hashes.

## 8. Existing ActiveChain audit inputs

The following materials are useful audit inputs at the time this draft was prepared. Their presence is not an audit conclusion.

| Evidence | Relevance | Auditor caveat |
| --- | --- | --- |
| [Project status](../../STATUS.md) | Tracks implemented and open development gates. | Checked boxes are management assertions until independently reproduced. Open items remain scope limitations or blockers. |
| [Pre-launch security-audit scope](../SECURITY_AUDIT.md) | Defines the existing technical audit requirement and publication gate. | It explicitly states that no security audit has been completed. |
| [Architecture guide](../ARCHITECTURE_GUIDE.md) | Integrates principals, keys, credentials, capabilities, policy, wallets, cash, proofs, and receipts. | Normative protocol specifications take precedence. |
| [P-001 canonical types and encoding](../../spec/protocol/P-001-canonical-types-and-encoding.md) | Canonical encoding and rejection boundary. | Auditor must test all parser and version-confusion paths. |
| [P-002 cryptographic suites](../../spec/protocol/P-002-cryptographic-suites.md) | Cryptographic suites and domains. | Requires independent cryptographic implementation review. |
| [P-010 state transition](../../spec/protocol/P-010-state-transition.md) | State-transition semantics. | Must be tied to production code and deployed configuration. |
| [P-020 principal lifecycle](../../spec/protocol/P-020-principal-lifecycle.md) | Stable principals, rotation, recovery, and revocation. | A principal is not, by itself, a KYC identity. |
| [P-021 credentials](../../spec/protocol/P-021-credentials.md) | Off-chain credentials, issuer/schema acceptance, status and freshness, fail-closed facts. | Current public profile exposes verified schema facts; it does not itself perform document verification, sanctions screening, or KYC operations. |
| [P-022 capabilities](../../spec/protocol/P-022-capabilities.md) | Attenuated authority and revocation. | Auditor must test every composition and escalation boundary. |
| [P-023 APL](../../spec/protocol/P-023-authorization-policy-language.md) | Bounded, total, default-deny policy evaluation and atomic obligations. | A policy permit is only one term in complete authorization. |
| [P-040 action envelopes](../../spec/protocol/P-040-action-envelopes.md) | Canonical request and replay binding. | Must be tested across chain, genesis, session, restart, reorg, and version boundaries. |
| [P-090 native money](../../spec/protocol/P-090-native-money.md) | Immutable native-asset definition and constrained issuance paths. | Supply conservation and every exceptional path require independent proof and testing. |
| [P-091 payment settlement](../../spec/protocol/P-091-native-payment-settlement.md) | Exact amounts, evidence classes, monotonic lifecycle, and idempotency. | Provider adapters and production reconciliation remain separate audit objects. |
| [P-095 ActiveChain DID method](../../spec/protocol/P-095-activechain-did-method.md) | DID resolution over finalized state. | Credentials and private attributes must not be embedded in DID documents. |
| [P-100 testnet wallet/operator contract](../../spec/protocol/P-100-testnet-wallet-operator.md) | Local canonical construction and prohibition on private-key or unsigned-send node endpoints. | Current developmental gaps and production custody remain in scope. |
| [P-110 verifier compatibility](../../spec/protocol/P-110-verifier-compatibility.md) | Strict envelopes and machine-readable positive/negative vectors. | Compatibility tests do not replace semantic and cryptographic review. |
| [P-111 post-quantum zero knowledge](../../spec/protocol/P-111-post-quantum-zero-knowledge.md) | Proof-system boundary and claims. | Auditor must report exact proof-system assumptions and soundness scope. |
| [Formal artifacts](../../formal/) | Lean, Tamarin, TLA+, Verus, and production-code proof harnesses. | Formal claims are scoped; conformance to production is mandatory. |
| [Deterministic vectors](../../testing/vectors/) and [manifest](../../testing/vectors/manifest-v1.json) | Cross-implementation and malformed/tampered fixtures. | Auditor must regenerate and independently consume them. |
| [Deterministic-kernel CI](../../.github/workflows/kernel.yml) | Pinned toolchains, tests, proofs, conformance, release builds, and vector reproduction. | The current workflow uses a project-controlled self-hosted runner; the auditor must reproduce critical gates on auditor-controlled infrastructure. |
| [Testnet release checklist](../TESTNET_RELEASE.md) | Wallet, ingress, finality, restart, replay, and economics acceptance. | Developmental testnet acceptance is not production assurance. |
| [Mobile-wallet boundary](../mobile-wallet.md) | Rust/native boundary, secure storage, approvals, and recovery expectations. | iOS, Android, FFI, and hardware-backed signing require specialist audit. |
| [Testnet operations](../testnet-operations.md) | Operational procedures and deployments. | Auditor must compare actual deployment configuration and logs. |

## 9. Control protocol

For each applicable control, the auditor MUST record: **Applicable / Not applicable / Not examined**, evidence IDs, test IDs, exceptions, finding references, and a design and operating-effectiveness conclusion.

### 9.1 Governance, scope, and accountability

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| GOV-01 | The role-and-jurisdiction matrix is complete and approved. | Trace legal entities, services, assets, control rights, customers, and jurisdictions to contracts, code/config access, and actual operations. | No material activity, operator, issuer, or control right is omitted or mischaracterized. |
| GOV-02 | A current regulatory obligations register exists. | Inspect change monitoring, counsel memoranda, responsible owners, effective dates, and implementation tickets. | Applicable obligations are mapped to controls and reviewed after material legal or business changes. |
| GOV-03 | Governance and emergency powers are explicit. | Enumerate admin, upgrade, pause, freeze, issuer, bridge, treasury, CI, release, and infrastructure rights. Attempt unapproved changes. | No hidden or undocumented privileged route; powers are least-privilege, separated, logged, and recoverable. |
| GOV-04 | Conflicts and segregation of duties are controlled. | Test developer/reviewer/releaser, compliance/operations, alert/investigation/reporting, issuer/custodian, and reserve-attestor separation. | Incompatible duties require independent approval and cannot be bypassed by one person. |
| GOV-05 | Policy changes are versioned and reviewable. | Select all high-risk policy changes and a random sample of ordinary changes; inspect approval, testing, effective time, rollback, and notice. | Every production policy has an immutable version, owner, rationale, tests, and authorized release. |
| GOV-06 | Public claims are accurate and bounded. | Compare website, documentation, white papers, audit statements, asset claims, and deployment status to evidence. | No unsupported “audited,” “compliant,” “stable,” “reserved,” “private,” “final,” or “production ready” claim. |
| GOV-07 | Risk acceptance is accountable. | Inspect accepted findings and exceptions, compensating controls, expiry, ownership, and board/senior-management approval. | Critical risks are not accepted for production assurance; other acceptances are reasoned, time-bounded, and visible to the auditor. |

### 9.2 Core ledger integrity and fraud prevention

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| CORE-01 | Consensus-visible values have one canonical meaning. | Differentially decode/encode valid, malformed, overlong, duplicate, unordered, unknown-version, and trailing-data inputs across implementations and FFI. | All conforming implementations agree; every non-canonical form is rejected before semantic use. |
| CORE-02 | State transitions are deterministic and atomic. | Run identical blocks/actions on independent nodes and implementations; inject failures at every obligation and persistence boundary. | Identical pre-state and input produce identical receipt/post-root; failed actions have no partial semantic effect. |
| CORE-03 | Native and asset supply is conserved. | Recompute genesis, issuance, burn, fees, rewards, shielding, redemption, refunds, slashing, bridge, and recovery paths. Use property tests and adversarial sequences. | No unauthorized creation, double mint, omitted liability, overflow, underflow, or inconsistent total supply. |
| CORE-04 | Double spend and conflicting state use are prevented. | Submit duplicate, conflicting, reordered, batched, parallel, and cross-node spends before and after finality. | At most one conflicting transition finalizes; rejection is deterministic and persists across restart. |
| CORE-05 | Replay is prevented in every domain. | Replay across nonce, session, request ID, fee ticket, chain ID, genesis, fork/reorg, epoch, policy version, credential audience, bridge, and Travel Rule binding. | A valid authorization cannot be reused outside its exact intended domain, budget, validity, and state. |
| CORE-06 | Finality and receipts are not overstated. | Partition/reconnect validators, restart nodes, compare independent observers, and tamper with inclusion/state/finality evidence. | Clients credit only evidence meeting the documented finality rule; optimistic or provider status is never presented as finality. |
| CORE-07 | Authority is the intersection of all required terms. | Attempt actor forgery, capability widening, revoked/stale authority, missing credential evidence, policy-only permit, budget exhaustion, and failed obligation settlement. | Any missing or invalid term denies the action; no partial obligation settlement occurs. |
| CORE-08 | Delegation cannot escalate. | Generate child capabilities broader by resource, action, recipient, value, fee, time, use count, purpose, data, or delegation depth. | Every broader child is rejected; revocation and expiry are enforced at the correct finalized state. |
| CORE-09 | Cryptographic domains and suites are unambiguous. | Review parameter sets, transcript composition, domain tags, randomness, key provenance, rotation, downgrade, suite confusion, and side channels. | No cross-protocol signature/proof reuse, weak fallback, unbound field, or unsupported suite acceptance. |
| CORE-10 | Resource use is bounded before attacker-controlled allocation. | Fuzz codecs, policy, VM, proofs, RPC, FFI, ingress, mempool, state witnesses, and evidence envelopes; conduct network-abuse tests. | Inputs fail within documented CPU/memory/size limits without panic, unsafe state, or validator divergence. |
| CORE-11 | Upgrades preserve explicit semantics. | Test version negotiation, unsupported revisions, migration, rollback, mixed-version nodes, and stale clients. | Unknown or incompatible versions fail closed; migrations are deterministic, authorized, reversible where promised, and independently evidenced. |
| CORE-12 | Fraud-relevant logs and receipts are complete. | Reconcile accepted/rejected actions, policy decisions, approvals, fees, state roots, and privileged operations to finalized state. | Every consequential event is uniquely traceable without logging secrets or private evidence. |

### 9.3 Identity, KYC, KYB, beneficial ownership, and PEP controls

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| KYC-01 | Legal identity is explicitly distinguished from a chain principal. | Inspect schemas, UI, APIs, policies, and reports for address-equals-person assumptions. Test re-binding and credential sharing. | A regulated action relies on verified subject/holder binding and approved evidence, not address ownership alone. |
| KYC-02 | Individual identity is identified and verified from reliable, independent evidence. | Sample low-, standard-, and high-risk customers; inspect document/eID verification, liveness where used, duplicate/synthetic-identity controls, and exceptions. | Required attributes are verified to the profile's assurance level before service; failures cannot be manually bypassed without authorized exception handling. |
| KYC-03 | Legal persons and beneficial owners are verified. | Sample entities across structures and jurisdictions; trace incorporation, ownership, control, directors, authorized representatives, and beneficial owners to independent sources. | The operator knows and verifies the customer, controlling persons, and beneficial owners required by the applicable framework. |
| KYC-04 | Customer risk is assessed using documented factors. | Reperform scores for geography, product, channel, customer, ownership, delivery, transaction behavior, source of funds, and relevant adverse information. | Risk outcomes are explainable, reproducible, approved, and drive proportionate CDD/EDD and monitoring. |
| KYC-05 | PEP, family member, and close-associate controls operate. | Seed exact, alias, transliterated, date-of-birth, and near-match cases. Sample PEP cases, approvals, source-of-wealth/funds work, and ongoing monitoring. | PEP status is not treated as automatic wrongdoing, but required senior approval, EDD, and monitoring occur. |
| KYC-06 | Credential issuer and schema trust are governed. | Review issuer onboarding, keys, authorization, assurance mapping, schema meaning, suspension, compromise, and removal. | Only approved issuer/schema combinations produce policy facts; assurance is never upgraded by adapters or labels. |
| KYC-07 | Credential status, freshness, and holder binding fail closed. | Test missing, future, stale, revoked, suspended, wrong-subject, wrong-issuer, wrong-schema, wrong-audience, and replayed presentations. | Every failure returns no verified fact; revocation/freshness latency meets the regulated profile. |
| KYC-08 | CDD is ongoing and refreshed. | Inspect triggers for expiry, material profile change, ownership change, unusual activity, sanctions-list update, and risk escalation. | Stale or materially changed records cannot silently remain sufficient; refresh and restriction rules operate. |
| KYC-09 | Inability to complete CDD has a controlled outcome. | Test incomplete, contradictory, unverifiable, and abandoned onboarding and remediation cases. | The regulated service is not initiated or continued contrary to policy; escalation and consideration of reporting are documented. |
| KYC-10 | Data minimization and selective disclosure are enforced. | Inspect chain data, proofs, logs, analytics, backups, support tooling, and credential presentations. Attempt correlation and low-entropy commitment guessing. | Only necessary facts or commitments are exposed; raw KYC/KYB data remains protected off-chain and disclosures are purpose/audience bound. |

### 9.4 Sanctions, terrorist financing, and proliferation financing

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| SAN-01 | Applicable sanctions and targeted-financial-sanctions sources are defined. | Compare legal register to UN, EU, national, sectoral, geographic, ownership/control, and asset/address obligations relevant to the profile. | Sources, legal basis, owner, update method, and applicability are documented; dynamic lists are not hard-coded into consensus. |
| SAN-02 | Screening occurs at required lifecycle points. | Seed listed and near-match customers, beneficial owners, counterparties, issuers, validators where relevant, CASPs, and addresses at onboarding, refresh, and transaction time. | Required screening occurs before the regulated action and during the relationship; stale screening cannot satisfy policy. |
| SAN-03 | List freshness and emergency updates are controlled. | Measure provider-to-production latency; simulate urgent designation, correction, provider outage, rollback, and corrupted feed. | List version and digest are recorded; updates meet the approved SLA; high-risk outages fail safely or invoke approved contingency. |
| SAN-04 | Matching handles identity complexity and false positives. | Test aliases, transliteration, reordered names, dates/places of birth, nationality, identifiers, ownership/control, and weak identifiers. Review false-positive closures. | Matching is risk-calibrated, documented, quality-tested, and subject to competent human review where needed. |
| SAN-05 | On-chain and cross-chain exposure is assessed proportionately. | Test direct and indirect exposure, chain hopping, bridges, mixers/obfuscation, peel chains, rapid dispersal, and newly designated addresses. | Analytics limitations and thresholds are documented; relevant risk changes the decision or investigation path. |
| SAN-06 | Freeze, reject, suspend, return, or hold actions are legally and technically controlled. | Seed positive matches and test timing, permissions, finality, asset scope, customer communication, release, and regulator escalation. | Required action occurs without unauthorized value creation, evidence destruction, or global claims beyond the operator/asset's lawful control. |
| SAN-07 | Sanctions-evasion, TF, and PF typologies are monitored. | Test patterns involving high-risk jurisdictions, front entities, rapid layering, small repeated transfers, donation/crowdfunding abuse, trade/proliferation indicators, and offshore providers. | Scenarios produce reviewable alerts/cases at approved sensitivity and are periodically validated. |
| SAN-08 | Overrides, licences, exemptions, and match releases are controlled. | Inspect every positive-match override and a sample of false-positive releases. | Decisions cite authority/evidence, require independent approval, are time-bounded where relevant, and preserve a confidential audit trail. |

### 9.5 Transaction monitoring, fraud prevention, investigation, and reporting

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| TXM-01 | A documented business-wide and product-specific ML/TF/PF/fraud risk assessment exists. | Compare risks to products, customers, geographies, assets, privacy features, bridges, hosted/self-hosted flows, and actual activity. | Material inherent risks, controls, residual risks, assumptions, and owners are current and drive monitoring. |
| TXM-02 | Monitoring receives complete, accurate, and timely data. | Reconcile ledger, mempool/ingress, wallet, customer, Travel Rule, device, fiat/payment, bridge, sanctions, and case data. Inject missing/late/duplicated events. | Population completeness is evidenced; data-quality failures alert, block, or degrade safely according to policy. |
| TXM-03 | Typologies reflect virtual-asset and fraud risks. | Test structuring, velocity, fan-in/fan-out, layering, peel chains, chain hopping, mixers, ransomware, darknet, scams, stolen funds, mule behavior, account takeover, bridge loops, wash-like activity, and unexplained source/destination. | Required scenarios detect seeded cases and record explainable contributing facts. |
| TXM-04 | Detection thresholds and models are governed. | Inspect tuning, validation, back-testing, drift, false-negative review, false positives, model changes, and approvals. | Thresholds are risk-based rather than chosen only to reduce workload; material changes are independently validated. |
| TXM-05 | Alerts become controlled investigations. | Sample alerts across outcome, risk, analyst, asset, and age; inspect evidence, chronology, linked activity, QA, escalation, and closure rationale. | Cases are timely, complete, reproducible, access-controlled, and cannot be silently deleted or backdated. |
| TXM-06 | Suspicious and attempted activity is reported where required. | Inspect confidential procedures, filing timeliness, decision governance, rejected/attempted transactions, FIU requests, and post-filing monitoring. | The accountable entity can demonstrate prompt, independent reporting decisions without exposing report content publicly. |
| TXM-07 | Anti-tipping-off confidentiality is enforced. | Review customer messages, support access, logs, analytics, developer access, and on-chain data around investigations and reports. | No customer, public-chain, or unauthorized staff signal reveals that a report exists or is contemplated. |
| TXM-08 | Customer and payment fraud controls protect intent. | Test phishing/social engineering, beneficiary substitution, address poisoning, device change, credential reset, session hijack, unusual value/velocity, cooling-off, step-up approval, and recipient display. | High-risk events trigger proportionate friction or review; the UI-approved recipient, asset, amount, fee, and purpose exactly match the signed intent. |
| TXM-09 | Human review and customer redress are meaningful. | Inspect automated denials, false positives, complaints, appeals, bias testing, and reviewer authority. | Material adverse decisions have competent review where required, documented reasons, and a lawful redress path without weakening confidentiality. |
| TXM-10 | Monitoring effectiveness is measured and improved. | Inspect alert-to-case rates, confirmed fraud, loss, recovery, time to disposition, QA, law-enforcement feedback, missed-event reviews, and scenario retirement. | Metrics identify control weakness and result in tracked remediation rather than cosmetic volume targets. |

### 9.6 Travel Rule and self-hosted-address controls

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| TRV-01 | Applicability is determined per transfer and jurisdiction. | Test domestic/cross-border, CASP-to-CASP, self-hosted, batch, intermediary, below/above threshold, linked, and suspicious transfers. | The correct profile and data/verification requirement is selected; no threshold is assumed to remove risk-based duties. |
| TRV-02 | Required originator and beneficiary information is complete. | Seed missing, malformed, truncated, unsupported-character, conflicting, and unverifiable fields. | The message contains every field required by the applicable profile and validation detects omissions before release where required. |
| TRV-03 | Travel Rule data is transmitted securely off-chain. | Review mutual authentication, encryption, counterparty key validation, routing, confidentiality, integrity, replay protection, availability, and incident handling. | Personal data is not placed on the public ledger; only authorized counterparties receive it in advance of, simultaneously, or concurrently with the transfer as required. |
| TRV-04 | The off-chain message is bound to the exact transfer. | Substitute chain, asset, amount, addresses, account IDs, CASP IDs, nonce, expiry, batch member, and transaction intent. | Any substitution or replay invalidates the binding; acknowledgements and decisions are uniquely traceable. |
| TRV-05 | Counterparty CASPs are identified and risk-assessed. | Test licensed/registered, unlicensed, offshore, sanctioned, shell, nested, repeatedly incomplete, and unknown counterparties. | The operator can identify the counterparty and apply documented risk-based accept, request, restrict, reject, or terminate rules. |
| TRV-06 | Missing or incomplete information has a controlled outcome. | Send incomplete data repeatedly and at different lifecycle stages. | Risk-based request, reject, return, suspend, restriction, termination, escalation, and reporting logic operates and is evidenced. |
| TRV-07 | Self-hosted-address controls are risk-based. | Test ownership/control evidence, signed-message or wallet proof, micro-transfer methods, third-party address, smart contract, multisig, privacy wallet, and inability to prove control. | Information is obtained and held as required; ownership/control is assessed where required, including the EU EUR 1,000 trigger, without treating proof of key control as proof of legal identity. |
| TRV-08 | Data retention, retrieval, and correction are controlled. | Retrieve historical messages by transfer and authority request; test corrections, duplicates, deletion locks, and access logs. | Required records are timely retrievable, accurate, protected, purpose-limited, and retained/deleted under the applicable schedule. |
| TRV-09 | Interoperability does not reduce assurance. | Exchange messages with independent implementations; test version mismatch, optional fields, duplicate identifiers, and counterparty outage. | Unknown or weaker versions fail safely; no adapter drops required data or upgrades assurance. |
| TRV-10 | Travel Rule data is included in suspicious-activity assessment. | Seed repeated missing data, inconsistent identities, unusual self-hosted flows, and evasive counterparties. | Relevant anomalies flow into monitoring and case management without exposing confidential case state on-chain. |

### 9.7 Privacy, recordkeeping, and confidential evidence

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| PRIV-01 | A data inventory, purpose, legal basis, and role map exists. | Trace every KYC, credential, sanctions, monitoring, Travel Rule, wallet, device, and audit data element through collection, use, sharing, retention, and deletion. | Each data flow has a necessary purpose, accountable controller/processor, lawful basis, access owner, and retention rule. |
| PRIV-02 | Public-chain data is minimized. | Inspect schemas, commitments, nullifiers, receipts, DID records, events, error messages, and indexing APIs for direct and inferable personal data. | Raw identity and case data is absent; stable identifiers and low-entropy commitments are avoided or technically protected. |
| PRIV-03 | Confidential systems have strong security. | Test encryption, key management, HSM/KMS controls, access approval, least privilege, MFA, logging, export, support access, backups, and breach detection. | Unauthorized access, bulk export, or silent alteration is prevented or promptly detected; secrets and private evidence never enter public logs. |
| PRIV-04 | Retention and deletion address blockchain immutability. | Review retention schedules, legal holds, deletion/anonymization, off-chain key destruction, backups, and on-chain minimization. | The design does not promise deletion of immutable public data; personal data placed on-chain is demonstrably necessary and minimized. |
| PRIV-05 | High-risk processing is assessed. | Inspect DPIA or equivalent for KYC biometrics, sanctions/adverse information, blockchain analytics, automated decisions, cross-border transfers, and ZK correlation. | Risks, safeguards, residual risk, consultations, and approvals are documented before production use. |
| PRIV-06 | Automated decisions have quality and human controls. | Test data quality, discrimination, explainability, override, appeal, and meaningful human intervention where required. | Models do not silently make unsupported legal/factual conclusions; material adverse decisions receive appropriate review. |
| PRIV-07 | Recordkeeping is complete and tamper-evident. | Reconcile customer, transaction, policy, screening, alert, case, approval, filing, training, and privileged-action records. | Records are complete, time-synchronized, integrity-protected, searchable, and retained for the applicable period. |
| PRIV-08 | Public and confidential audit reporting are separated. | Review proposed GitHub report and confidential annex. Attempt to infer customers, matches, reports, vulnerabilities, or provider secrets from public hashes/metadata. | Public evidence is useful but non-sensitive; competent authorities and the auditor can access authorized confidential detail. |

### 9.8 Asset issuer, stablecoin, reserve, and market-integrity controls

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| AST-01 | The asset, issuer, offer, service, and legal classification are documented. | Compare legal opinions, terms, white paper/disclosures, marketing, code, actual control, and customer flow. | The asset is not launched or marketed under an unsupported classification or licence assumption. |
| AST-02 | Asset definitions and privileged roles are canonical and bounded. | Enumerate issuer, controller, mint, burn, redeem, freeze, seize, pause, upgrade, reserve-attestor, and bridge rights. Attempt role confusion and escalation. | Every power is disclosed, least-privilege, separately authorized, versioned, and visible to wallets/verifiers. |
| AST-03 | Issuance, redemption, and burn reconcile to liabilities. | Reperform every issuance/redemption during the period and sample ordinary transfers; reconcile chain supply, pending items, fees, and off-chain liabilities. | No issuance without authorization and consideration/reserve evidence; no redemption or burn mismatch; breaks are promptly resolved. |
| AST-04 | Reserve assets are sufficient, segregated, and controlled where claimed. | Obtain independent custodian/bank confirmations, legal title, encumbrance analysis, asset eligibility, valuation, concentration, liquidity, and cut-off tests. | Reserve claims match confirmed assets and liabilities at the stated time; customer/issuer assets are treated as represented. |
| AST-05 | Reserve evidence cannot be stale, substituted, or overstated. | Substitute period, issuer, asset, custodian, account, liability snapshot, signature, and attestor; test revocation and late reporting. | Evidence binds exact issuer/asset/liability/time and assurance class; stale or weaker evidence cannot satisfy a stronger policy. |
| AST-06 | Exceptional controls are lawful, transparent, and reviewable. | Test freeze/release, denylist, court/order execution, compromise response, error correction, and appeal. | Actions are scoped, authorized, reasoned in confidential records, independently approved, and cannot create value or hide liabilities. |
| AST-07 | Customer disclosures are accurate and timely. | Inspect rights, redemption, fees, reserves, risks, conflicts, governance, technology, finality, privacy, and audit status. | Disclosures match code and operations; “stable,” “fully backed,” “audited,” or “redeemable” claims are evidenced and qualified. |
| AST-08 | Market abuse and conflicts are addressed where applicable. | Review treasury/employee trading, listings, market making, inside information, order/transaction surveillance, and related-party transactions. | Conflicts are disclosed and controlled; suspicious or abusive patterns are investigated and escalated. |

### 9.9 Wallet, custody, recovery, and user authorization

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| WAL-01 | Nodes and services never accept private keys or unsigned “send” shortcuts. | Inspect RPC/API/CLI/FFI, debug routes, support tooling, logs, and hidden feature flags. | Canonical intents are constructed and approved at the authorized signer boundary; no plaintext private key leaves custody. |
| WAL-02 | Key generation, storage, and signing are protected. | Review entropy, derivation, Secure Enclave/Keychain, Android Keystore, HSM, hardware wallet, enclave fallback, attestation, export, zeroization, and side channels. | Secret material is non-exportable where promised; fallback and recovery do not silently reduce assurance. |
| WAL-03 | Human approval matches the signed transaction. | Manipulate asset ID/symbol, decimals, recipient, amount, fee, network, memo/purpose, contract effects, and post-approval payload. | The exact canonical bytes/effects shown and approved are those signed; ambiguous or blind signing is blocked or explicitly risk-labelled. |
| WAL-04 | Recovery, rotation, revocation, and compromise response are safe. | Test lost device, stolen device, compromised controller, recovery authority compromise, multi-device races, pending/finalized revocation, and backup restore. | Recovery cannot widen authority or bypass policy; compromise invalidates affected sessions/capabilities and preserves auditable continuity. |
| WAL-05 | Sessions and agents have bounded authority. | Exhaust budgets/use counts, extend expiry, alter purpose/recipient, replay requests, rotate agent keys, and remove a local app without on-chain revocation. | Limits and final revocation are enforced by validators; local UI state is never treated as global authority. |
| WAL-06 | Backups and logs do not leak secrets. | Inspect local/cloud backups, crash reports, analytics, clipboard, screenshots, notifications, app groups, browser handoff, and support bundles. | No plaintext key, reusable bearer capability, raw credential, or sensitive transaction evidence is exposed. |
| WAL-07 | Hosted custody has institutional controls where applicable. | Test withdrawal approval, whitelists, velocity, cold/hot segregation, reconciliation, privileged access, key ceremonies, disaster recovery, and insider threat. | Customer assets and authorization are protected by documented multi-person, technical, and reconciliation controls. |
| WAL-08 | FFI and mobile surfaces receive specialist independent review. | Fuzz pointer/length/lifetime/version boundaries, panic/unwind, native callbacks, UI race conditions, and secure-storage attributes. | No memory-safety, secret-exposure, approval-confusion, or ABI-version bypass remains unresolved at Critical/High severity. |

### 9.10 Bridges, payment connectors, external providers, and oracles

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| EXT-01 | Provider-specific code remains outside consensus. | Inspect validator dependencies and inputs; inject provider payloads/status directly into consensus paths. | Consensus accepts only canonical, authenticated, bounded evidence of a declared class and never parses ambient provider JSON. |
| EXT-02 | Evidence assurance cannot be upgraded. | Replace final/confirmed evidence with observed/pending/provider-asserted evidence, substitute source, or remove proof fields. | Weaker, stale, unauthenticated, or mismatched evidence never satisfies a stronger class. |
| EXT-03 | External lifecycle transitions are monotonic and idempotent. | Duplicate callbacks, reorder statuses, retry after timeout/crash, send conflicting providers, and replay old quotes. | Repeated events have one result; invalid regressions/conflicts are quarantined; no duplicate payment, mint, refund, or credit occurs. |
| EXT-04 | Bridge conservation is independently proved and reconciled. | Reperform lock/mint, burn/unlock, fee, refund, emergency, reorg, validator-set change, and message replay paths across both chains. | Assets cannot be minted/unlocked twice or without final source evidence; liabilities and locked assets reconcile. |
| EXT-05 | Quotes, prices, and oracles are exact and fresh. | Alter asset ID, units, decimals, source, timestamp, expiry, spread, signature, quorum, and fallback. | No floating-point or display-symbol ambiguity; stale/manipulated data is rejected or safely bounded. |
| EXT-06 | Counterparty and offshore-provider risk is assessed. | Review provider licensing/registration, ownership, sanctions, controls, location, subcontractors, nesting, and termination plans. | High-risk or unknown providers receive proportionate due diligence, limits, monitoring, and escalation. |
| EXT-07 | Reconciliation detects external breaks. | Reconcile chain state, provider state, bank/custodian records, customer ledger, fees, pending items, and exceptions across cut-off. | Breaks are complete, aged, owned, investigated, and cannot be cleared without evidence. |
| EXT-08 | Provider outage or compromise fails safely. | Simulate unavailable, slow, equivocal, malicious, or compromised provider and leaked API keys. | No external outage creates false finality, duplicate value, uncontrolled retries, or silent compliance bypass. |

### 9.11 Operations, validators, incidents, and third parties

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| OPS-01 | Production deployment matches the audited release. | Hash binaries, containers, genesis, configs, feature flags, policies, schemas, and infrastructure; compare across nodes and regions. | No unreviewed drift or hidden debug/override path; deviations are approved and independently assessed. |
| OPS-02 | Validator and network resilience are tested. | Exercise restart, crash-atomic persistence, snapshot restore, partition, eclipse, equivocation, clock issues, resource exhaustion, and quorum loss. | Safety properties hold; recovery does not lose replay barriers or create conflicting finalized state. |
| OPS-03 | Security, fraud, AML, privacy, and sanctions incidents have integrated response. | Run tabletop and technical exercises for key compromise, unauthorized mint, double spend, provider breach, sanctions designation, data breach, fraud wave, and monitoring outage. | Detection, containment, legal/regulatory escalation, customer protection, evidence preservation, recovery, and lessons learned are timely and owned. |
| OPS-04 | Authority and FIU requests are handled lawfully and promptly. | Inspect intake, authentication, scope validation, preservation, response, privilege, logging, and emergency procedures. | Authorized requests are answered fully and securely within applicable deadlines; unauthorized disclosure is prevented. |
| OPS-05 | Personnel controls match access risk. | Sample background/suitability checks where lawful, onboarding, training, access grants, role changes, leave, termination, and conflicts. | Privileged and compliance staff are trained and access is removed promptly; sensitive actions are monitored. |
| OPS-06 | Third parties are governed. | Review KYC, analytics, sanctions, Travel Rule, cloud, wallet, custody, bridge, attestor, and audit vendors. Test outage and exit. | Contracts, due diligence, data terms, SLAs, assurance, incidents, subcontractors, and exit plans address the actual risk. |
| OPS-07 | Whistleblowing and independent escalation exist. | Inspect channels, non-retaliation, board/audit oversight, and treatment of prior concerns. | Staff can report fraud, compliance, security, or management override concerns outside the normal chain of command. |
| OPS-08 | Operational metrics are complete and actionable. | Review uptime, finality, reorgs, rejected actions, replay attempts, privileged changes, fraud losses, alerts/cases, sanctions latency, Travel Rule failures, data incidents, and remediation age. | Metrics are reconciled, reviewed by accountable governance, and produce documented action. |

### 9.12 Software development, build, release, and formal assurance

| ID | Requirement | Auditor procedure | Minimum pass condition |
| --- | --- | --- | --- |
| SDLC-01 | The audit and release scope is immutable and reproducible. | Build the frozen commit from a clean checkout; verify lockfiles, submodules, toolchains, images, and artifact hashes. | Auditor-controlled builds succeed and match documented outputs or explain reproducible platform-specific differences. |
| SDLC-02 | Dependencies and supply chain are controlled. | Generate SBOM, inspect provenance, pinned actions/images, vulnerabilities, abandoned packages, licences, build scripts, proc macros, and transitive native code. | No unresolved Critical/High supply-chain risk; mutable or unauthenticated dependencies are eliminated from release paths. |
| SDLC-03 | Changes receive independent review and tests. | Sample security/compliance-critical commits and all privileged emergency changes; trace issue, design, review, tests, merge, release, and rollback. | No single developer can silently modify and release critical semantics or regulated policy. |
| SDLC-04 | CI is not the sole trust root. | Re-run critical checks outside project-controlled self-hosted infrastructure; compare logs and artifacts. | Results are independently reproducible and not dependent on undocumented runner state or credentials. |
| SDLC-05 | Formal claims are scoped and connected to implementation. | Inspect theorem statements, assumptions, model abstraction, production-code harnesses, differential fixtures, and counterexamples. | Public claims match proved properties; conformance gaps are explicit and no whole-system “proof” is inferred. |
| SDLC-06 | Negative, property, differential, and fuzz tests cover abuse. | Review coverage against threat model and seed parser, replay, authority, supply, state, FFI, wallet, bridge, and compliance-evidence failures. | Security-relevant failure classes have deterministic tests; fuzzing reaches meaningful semantic boundaries. |
| SDLC-07 | Release signing and secrets are protected. | Review key ceremonies, signing infrastructure, branch protections, tag verification, package publishing, mobile signing, emergency rotation, and revocation. | Release authenticity is independently verifiable and one compromised account cannot publish a trusted release. |
| SDLC-08 | Findings block release appropriately. | Trace open issues, launch gates, accepted risks, and release claims. | Unresolved Critical/High findings and mandatory open gates block the corresponding production assurance module. |

## 10. Mandatory independent test catalogue

The tests below are minimum scenarios. The auditor SHOULD extend them based on the threat model and implementation. Each test record MUST include preconditions, exact frozen artifacts, input vectors, expected result, actual result, logs/hashes, evidence IDs, tester, date, and deviations.

### 10.1 Core and fraud tests

| Test ID | Scenario | Expected result |
| --- | --- | --- |
| T-CORE-001 | Regenerate all canonical vectors and consume them with at least one independent implementation. | Byte-for-byte agreement; malformed/tampered vectors fail with the expected class. |
| T-CORE-002 | Add trailing bytes, non-minimal lengths, duplicate facts, unordered facts, unknown tags, and oversized values. | Rejected before semantic use; no panic or differential interpretation. |
| T-CORE-003 | Attempt unauthorized native issuance and invoke every reward, shielding, refund, burn, redemption, and recovery path in adversarial order. | Supply equation remains exact; no double mint or omitted liability. |
| T-CORE-004 | Submit conflicting spends concurrently to every validator and ingress path. | At most one finalizes; all nodes converge. |
| T-CORE-005 | Replay a valid action after process crash, snapshot restore, node replacement, reorg, and network reconnect. | Persistent replay barriers reject every duplicate. |
| T-CORE-006 | Substitute chain ID, genesis, nonce, session, recipient, value, fee, policy, credential, proof image, or journal. | Signature/proof/commitment verification fails. |
| T-CORE-007 | Make APL permit while actor, capability, credential, budget, or obligation settlement is invalid. | Complete authorization denies atomically. |
| T-CORE-008 | Widen a delegated capability one dimension at a time and through composition. | Every widening is rejected. |
| T-CORE-009 | Partition validators, create competing observations, then reconnect. | Documented safety/finality rules hold; clients do not credit weaker evidence. |
| T-CORE-010 | Exhaust parser, policy, VM, proof, state-witness, RPC, and ingress resource bounds. | Bounded rejection without unsafe allocation, crash, or consensus divergence. |
| T-CORE-011 | Upgrade and downgrade mixed-version nodes and clients. | Incompatible semantics fail closed; no silent fallback. |
| T-CORE-012 | Compare finalized receipts and state roots across independently built nodes. | Deterministic equality for identical pre-state/input. |

### 10.2 Identity and KYC tests

| Test ID | Scenario | Expected result |
| --- | --- | --- |
| T-KYC-001 | Present a valid credential for the wrong subject, principal, audience, chain, purpose, or transaction. | No verified fact is produced. |
| T-KYC-002 | Present missing, future, stale, suspended, revoked, wrong-registry, or wrong-sequence status evidence. | Fail closed with no policy fact. |
| T-KYC-003 | Use an approved schema from an unapproved issuer and an approved issuer with an unapproved schema. | Both fail. |
| T-KYC-004 | Attempt to upgrade self-issued or lower-assurance evidence into regulated identity. | Adapter and policy reject the assurance upgrade. |
| T-KYC-005 | Reuse or transfer another person's holder-bound credential/presentation. | Holder/subject binding and replay/nullifier controls reject it. |
| T-KYC-006 | Onboard a legal entity with hidden layered ownership and a changed beneficial owner. | Required ownership/control is discovered; change triggers refresh and risk review. |
| T-KYC-007 | Seed PEP aliases, family/associate links, and false positives. | Correct EDD/escalation occurs without automatic unsupported denial. |
| T-KYC-008 | Remove one required CDD element or make evidence contradictory. | Regulated service cannot proceed under a complete-profile policy. |

### 10.3 Sanctions, TF, and PF tests

| Test ID | Scenario | Expected result |
| --- | --- | --- |
| T-SAN-001 | Designate a customer/counterparty after onboarding and before a transfer. | Update reaches production within SLA; required hold/review/action occurs. |
| T-SAN-002 | Corrupt, roll back, or make the sanctions feed unavailable. | Integrity/freshness controls alert and the regulated profile fails safely or uses approved contingency. |
| T-SAN-003 | Test exact, alias, transliterated, partial, reordered, date-of-birth, and identifier matches. | Matching and analyst review follow the documented methodology. |
| T-SAN-004 | Test direct and indirect listed-address exposure through peel chains, bridges, and chain hopping. | Risk is detected according to validated thresholds and limitations. |
| T-SAN-005 | Attempt an override using an unauthorized user or without licence/exemption evidence. | Override fails and is logged. |
| T-SAN-006 | Release a false positive and then replay the old positive decision or old list version. | Decision is correctly versioned; stale decisions cannot authorize new activity. |
| T-SAN-007 | Seed terrorist-financing and proliferation-financing typologies using small repeated values and front entities. | Monitoring creates prioritized, confidential cases. |
| T-SAN-008 | Query public chain/indexer data for sanctions or STR status. | No sensitive match, case, or report status is exposed. |

### 10.4 Transaction-monitoring and fraud tests

| Test ID | Scenario | Expected result |
| --- | --- | --- |
| T-TXM-001 | Remove or delay one source-data stream. | Data-quality control detects the gap and invokes approved block/degradation/escalation. |
| T-TXM-002 | Seed structuring, rapid fan-in/fan-out, peel chain, mixer, ransomware, scam, mule, account takeover, and bridge-loop patterns. | Appropriate alerts/cases are generated with explainable evidence. |
| T-TXM-003 | Split related activity across identities, assets, addresses, chains, and time windows. | Entity/link analysis or compensating review detects the designed scenario. |
| T-TXM-004 | Alter thresholds to suppress workload without approval. | Change control prevents deployment or detects unauthorized drift. |
| T-TXM-005 | Attempt to delete, backdate, or silently close an alert/case. | Integrity and authorization controls prevent or detect it. |
| T-TXM-006 | Seed an attempted/rejected suspicious transfer. | It remains available for assessment and reporting despite non-completion. |
| T-TXM-007 | Manipulate wallet display after approval or poison a recipient address. | Signed intent remains exact; high-risk change requires new approval. |
| T-TXM-008 | Trigger automated denial on a false positive. | Meaningful review/redress operates without revealing confidential monitoring or STR logic. |

### 10.5 Travel Rule and self-hosted-address tests

| Test ID | Scenario | Expected result |
| --- | --- | --- |
| T-TRV-001 | Omit each required originator and beneficiary field one at a time. | Validation detects the omission and the configured request/reject/suspend path runs. |
| T-TRV-002 | Send Travel Rule data after the transfer when the profile requires advance/simultaneous transmission. | Transfer is not released contrary to policy. |
| T-TRV-003 | Put personal Travel Rule fields in an on-chain memo/event. | Schema/policy rejects the payload or test identifies a release-blocking privacy defect. |
| T-TRV-004 | Bind a valid message to a different chain, asset, amount, address, CASP, or transaction. | Binding verification fails. |
| T-TRV-005 | Replay a valid Travel Rule message and acknowledgement. | Duplicate/replay is rejected idempotently. |
| T-TRV-006 | Use unknown, unlicensed, sanctioned, shell, or repeatedly incomplete counterparty CASPs. | Risk-based counterparty controls invoke the documented outcome. |
| T-TRV-007 | Send above and below EUR 1,000 to/from a self-hosted address, including linked transfers. | EU profile obtains/holds required information and assesses ownership/control when required; linked and suspicious activity is not evaded by splitting. |
| T-TRV-008 | Prove key control for an address owned legally by another person. | System distinguishes cryptographic control from legal ownership/beneficial ownership and escalates as required. |

### 10.6 Asset, reserve, bridge, and payment tests

| Test ID | Scenario | Expected result |
| --- | --- | --- |
| T-AST-001 | Invoke mint, burn, redeem, freeze, and release using every role and unauthorized role. | Only exact authorized role/policy paths work; all effects are auditable. |
| T-AST-002 | Substitute reserve evidence from another asset, issuer, account, custodian, or date. | Evidence binding rejects substitution. |
| T-AST-003 | Backdate liabilities or exclude pending redemptions at reserve cut-off. | Reconciliation and cut-off testing identify the understatement. |
| T-AST-004 | Make reserve or attestation evidence stale. | Strong reserve-backed policy no longer passes; customer disclosures reflect the state. |
| T-EXT-001 | Duplicate/reorder provider callbacks and crash between external and local persistence. | No duplicate credit, mint, refund, or settlement. |
| T-EXT-002 | Present provider “success” without ActiveChain finality evidence. | Client and consensus do not treat it as finality. |
| T-EXT-003 | Reorg the source chain after bridge observation at each assurance level. | Destination action follows the declared finality/assurance rule and cannot over-credit. |
| T-EXT-004 | Compromise an API key or provider signer. | Scope, monitoring, rotation, and reconciliation contain the incident. |

### 10.7 Wallet, privacy, and operations tests

| Test ID | Scenario | Expected result |
| --- | --- | --- |
| T-WAL-001 | Search binaries, memory, logs, backups, analytics, notifications, crash dumps, and clipboard for keys/credentials. | No plaintext secret or prohibited personal evidence is present. |
| T-WAL-002 | Race UI approval, signing callback, app lifecycle, and transport submission. | Approved canonical intent cannot be replaced or signed twice unexpectedly. |
| T-WAL-003 | Restore an old backup after rotation/revocation. | Stale authority cannot regain control or revive spent sessions. |
| T-PRIV-001 | Enumerate likely low-entropy facts against public commitments. | Commitments are salted/blinded or otherwise non-enumerable. |
| T-PRIV-002 | Correlate repeated ZK presentations/nullifiers across audiences and purposes. | Pairwise/policy-scoped design prevents correlation beyond documented limits. |
| T-OPS-001 | Restore validators and compliance systems from backup after abrupt failure. | Ledger, replay barriers, cases, list versions, and evidence are consistent and complete. |
| T-OPS-002 | Conduct integrated key-compromise/unauthorized-mint/sanctions/data-breach tabletop. | Roles, decisions, evidence preservation, authority notifications, and recovery meet the plan. |
| T-OPS-003 | Compare live deployment hashes/configuration to the frozen audit package. | Unauthorized drift is absent or detected and remediated. |

## 11. Existing reproducible commands

At the frozen audit commit, the auditor SHOULD first execute the repository's documented gates, then repeat critical tests using auditor-authored harnesses. Current commands visible across the [deterministic-kernel workflow](../../.github/workflows/kernel.yml) and [testnet release checklist](../TESTNET_RELEASE.md) include:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

(cd formal/lean && lake build)
bash scripts/check-formal-models.sh
bash scripts/check-kani-codec.sh
bash scripts/check-kani-verifier-ffi.sh
bash scripts/check-kani-object-vm.sh
bash scripts/check-kani-protocol-types.sh
bash scripts/check-kani-commitment.sh
formal/verus/verify.sh
bash scripts/check-proof-conformance.sh

cargo test --locked --workspace --all-features
cargo test --locked --workspace --doc
cargo build --locked --workspace --release
cargo test --locked --workspace --release

bash scripts/rehearse-validator-processes.sh
bash scripts/rehearse-live-process-quorum.sh
bash scripts/check-verifier-manifest.sh
cargo test -p activechain-verifier-api
```

The workflow also regenerates canonical vectors and cross-checks Rust and Lean semantic tables. The auditor MUST inspect the frozen workflow rather than assuming this list is complete.

The auditor MUST NOT rely solely on the project's self-hosted CI runner. At least the release build, workspace tests, formal-model checks, production-code proof harnesses, proof conformance, vector reproduction, validator rehearsals, and high-risk negative tests MUST be run on auditor-controlled infrastructure with preserved logs and artifact hashes.

## 12. Required new public evidence for regulated profiles

The following artifacts are recommended before requesting a FINANCIAL-CRIME-OPS, REGULATED-TRANSFER, or ASSET-ISSUER opinion. These paths are proposed and are not represented as currently implemented.

```text
docs/audits/AUDITOR_ASSURANCE_PROTOCOL.md
docs/compliance/ROLE_JURISDICTION_MATRIX.md
docs/compliance/COMPLIANCE_BOUNDARY.md
docs/compliance/REGULATORY_CHANGE_LOG.md
docs/compliance/PRIVACY_AND_DATA_BOUNDARY.md
docs/compliance/TRAVEL_RULE_PROFILE.md
docs/compliance/SANCTIONS_AND_SCREENING_PROFILE.md
docs/compliance/TRANSACTION_MONITORING_CONTROL_SPEC.md
docs/compliance/ASSET_ISSUER_CONTROL_PROFILE.md
spec/protocol/P-120-compliance-evidence.md
spec/protocol/P-121-regulated-transfer-binding.md
testing/vectors/compliance/
testing/vectors/travel-rule/
testing/vectors/sanctions/
testing/vectors/issuer-controls/
scripts/check-compliance-vectors.sh
audit/evidence-manifest.json
audit/reports/
audit/remediation/
```

Public specifications SHOULD define semantics, schemas, privacy boundaries, negative cases, and evidence commitments. Confidential operating procedures SHOULD contain provider configuration, customer data, match logic, case rules, reporting channels, and exploitable details.

## 13. Recommended future protocol boundary for compliance evidence

This section is a design recommendation, not a statement about current implementation.

ActiveChain SHOULD expose narrowly scoped, versioned evidence primitives that allow a regulated operator or asset policy to require verified facts without placing personal data or suspicious-activity state on-chain.

### 13.1 `CompliancePolicyProfileV1`

A profile SHOULD bind:

```text
profile_id
profile_revision
operator_principal
jurisdiction_set_commitment
regulated_activity_class
applicable_asset_or_resource_selectors
required_credential_schema_and_issuer_sets
required_screening_assurance_class
maximum_screening_age
required_Travel_Rule_profile
self_hosted_address_rules
required_approval_roles
transaction_value_and_risk_limits
monitoring_receipt_requirement
privacy_and_disclosure_policy_commitment
valid_from_and_valid_until
supersedes_profile
profile_governance_signature
```

Jurisdiction and sanctions content SHOULD be versioned through authorized registries or commitments, not hard-coded permanently into consensus.

### 13.2 `ComplianceEvidenceEnvelopeV1`

The envelope SHOULD contain only facts necessary for deterministic policy enforcement and audit binding:

```text
format_version
profile_id_and_revision
chain_id_and_genesis
operator_principal
subject_or_pairwise_binding
credential_fact_commitments
issuer_and_status_evidence_commitments
screening_provider_and_assurance_class
screening_policy_and_list_set_commitment
screened_at_and_valid_until
Travel_Rule_message_commitment_and_counterparty_binding
optional_self_hosted_control_evidence_commitment
action_or_transaction_intent_commitment
purpose_and_audience
nonce_or_single_use_identifier
verifier_principal_and_signature
```

The envelope MUST NOT expose a person's name, date of birth, address, document number, beneficial-owner details, PEP status, sanctions-match result, risk score, case status, source-of-funds documents, or STR/SAR state. Where policy needs a private predicate, a verifier may attest or prove only the minimum result, such as “the required regulated-transfer profile was satisfied for this exact action before expiry.”

A positive envelope does not certify that the customer is “safe.” It certifies that named controls were executed under a named policy and evidence version for the exact action.

### 13.3 `TravelRuleBindingV1`

Travel Rule personal data SHOULD travel through an authenticated, encrypted, off-chain channel. The chain-visible binding MAY include:

```text
message_profile_and_version
originator_CASP_principal
beneficiary_CASP_principal
encrypted_message_commitment
exact_transfer_intent_commitment
created_at_and_expiry
acknowledgement_state_commitment
single_use_identifier
sender_and_receiver_signatures
```

The binding MUST support request, accepted, rejected, returned, suspended, and expired outcomes without publishing the personal fields or confidential reason.

### 13.4 `ControlExecutionReceiptV1`

A confidential control system MAY issue an audit receipt committing to:

```text
control_id_and_revision
evidence_population_or_case_reference_commitment
execution_time
outcome_class_without_sensitive_reason
operator_or_reviewer_role
source_system_and_configuration_commitment
retention_locator_commitment
auditor_verifiable_signature
```

Receipts MUST be non-enumerable, access-controlled, and designed so their public presence does not reveal that a person was screened, investigated, sanctioned, or reported.

### 13.5 Policy composition

For a regulated transfer, authorization SHOULD remain an intersection:

```text
authenticated actor
AND valid non-revoked attenuated authority
AND current verified identity/credential facts required by the profile
AND current screening/control evidence required by the profile
AND exact Travel Rule binding when applicable
AND APL permit
AND no protocol or profile forbid
AND atomic settlement of approvals, budgets, holds, audit commitments, and other obligations
```

The base protocol SHOULD remain honest about what it cannot observe. Transaction monitoring, customer risk, provider due diligence, case investigation, reporting, and legal decision-making remain accountable off-chain functions even when their minimal receipts are cryptographically bound.

## 14. Sampling and operating-effectiveness protocol

### 14.1 Observation period

An S3 opinion MUST state its exact observation period. Ninety days is the minimum recommended period for a newly operational profile; a mature annual review SHOULD normally examine at least six months and include period-end cut-off. A shorter period MUST be clearly qualified.

### 14.2 Population completeness

Before sampling, the auditor MUST establish complete populations for:

- customers, beneficial owners, PEPs, risk ratings, refreshes, and closures;
- sanctions-screening events, potential matches, overrides, and list updates;
- transfers, self-hosted flows, Travel Rule messages, missing-data events, and counterparty CASPs;
- monitoring alerts, cases, escalations, suspicious-activity decisions, attempted transactions, and regulator/FIU requests;
- fraud events, complaints, reimbursements/recoveries, account takeovers, and manual overrides;
- asset issuance, redemption, burn, freeze/release, reserve snapshots, and reconciliation breaks;
- bridge/payment events, retries, conflicts, refunds, and exceptions;
- privileged access, policy/config changes, releases, incidents, outages, and findings.

Completeness MUST be reconciled to independent source totals such as finalized chain state, banking/custodian records, identity-provider billing or logs, sanctions-provider logs, message gateways, and immutable system audit logs.

### 14.3 Mandatory 100% review populations

The auditor MUST examine 100% of:

- confirmed or unresolved sanctions matches and all overrides/licences/exemptions;
- suspicious-transaction reports and non-filing decisions classified high risk, using a confidential process that does not disclose their existence publicly;
- material fraud losses, unauthorized mint/supply events, key compromises, data breaches, and regulatory incidents;
- privileged or emergency production changes;
- issuer mint/burn/redemption exceptions and material reserve breaks;
- Critical and High findings and their remediation;
- repeated Travel Rule data failures and high-risk counterparty restrictions/terminations; and
- control-owner or senior-management overrides of automated or analyst decisions.

Other populations MUST use documented risk-based and random sampling sufficient to support the stated conclusion. The auditor, not management, selects the sample.

### 14.4 Re-performance

For automated controls, the auditor SHOULD independently reperform the logic against a protected copy of the complete population or a cryptographically verifiable test population. For high-risk models and transaction-monitoring scenarios, the auditor SHOULD use seeded cases, back-testing, threshold sensitivity, and false-negative review rather than relying only on alert samples.

## 15. Findings and severity

| Severity | Definition | Release treatment |
| --- | --- | --- |
| **Critical** | Credible path to unauthorized value creation, systemic double spend/finality failure, compromise of broad signing authority, complete regulated-control bypass, falsified audit/reserve evidence, or catastrophic confidential-data exposure. | Blocks every affected production module. Immediate containment and independent re-review required. |
| **High** | Material loss, broad authorization escalation, repeatable KYC/sanctions/Travel Rule bypass, serious monitoring/reporting failure, major bridge/custody weakness, or significant privacy breach with realistic exploitation. | Blocks affected production assurance until fixed and re-reviewed. |
| **Medium** | Important weakness requiring conditions, limited exploitation, compensating controls, or material process inconsistency. | Remediation deadline and explicit qualified conclusion; may block depending on aggregate risk. |
| **Low** | Limited impact or defense-in-depth weakness. | Track to closure; disclose if relevant to conclusions. |
| **Observation** | Improvement or clarification without demonstrated control failure. | No pass/fail effect unless combined with other evidence. |

Severity MUST consider impact, likelihood, exploitability, affected population/value, detectability, legal consequence, privacy, reversibility, and whether a malicious insider or external actor can use the weakness.

Every finding MUST include:

```text
finding_id
control_and_test_ids
scope_and_affected_versions
severity_and_rationale
condition
expected_requirement
root_cause
impact
reproduction_or_evidence
management_response
remediation_owner_and_due_date
fix_commit_and_configuration
independent_retest_result
residual_risk_and_limitations
public_or_confidential_classification
```

A finding is not closed because code changed. Closure requires evidence that the root cause is remediated, tests cover regression, deployment is updated, and the independent auditor has re-tested it.

## 16. Audit conclusion, report, and publication

### 16.1 Permitted results

Each module receives one result:

- **Pass** — requirements in scope are met at the stated stage and period, with no unresolved finding that changes the conclusion.
- **Pass with limitations** — the conclusion is positive only within explicit material limitations or conditions.
- **Fail** — one or more material requirements are not met.
- **Not examined** — insufficient scope or evidence; no conclusion.
- **Not applicable** — reasoned and evidenced non-applicability for the named role/profile.

### 16.2 Required public report contents

The published report MUST include:

1. auditor identity, competence, independence, and conflicts;
2. audit sponsor and accountable legal entities;
3. modules, roles, jurisdictions, assets, services, deployment, and excluded scope;
4. frozen commit, release, binary/configuration/genesis/policy hashes, and observation period;
5. assurance stage and methods;
6. evidence-manifest hash and public evidence links;
7. test summary, independent reproduction environment, and sampling method;
8. result by module and control domain;
9. all public findings, remediation status, and accepted limitations;
10. explicit statement that public code or protocol primitives do not replace operator legal obligations; and
11. signature, issue date, expiry/reassessment triggers, and version history.

### 16.3 Confidential annex

The auditor MAY maintain a confidential annex for competent authorities and authorized governance containing sensitive work papers, customer/case samples, sanctions results, STR/SAR testing, provider settings, exploit detail under remediation, reserve confirmations, and personal data. The public report SHOULD identify the existence and hash of the annex without revealing its sensitive contents.

### 16.4 Validity and reassessment

An audit conclusion expires at the earliest of:

- the report's stated expiry, which SHOULD NOT exceed 12 months for a production regulated profile;
- a material protocol, cryptographic, wallet, policy, issuer, bridge, provider, or operational change;
- deployment of code/configuration outside the audited hashes;
- a Critical or material High vulnerability or incident;
- a material change in legal entity, ownership, control, regulated activity, jurisdiction, licence, or asset terms;
- a material failure or replacement of KYC, sanctions, analytics, Travel Rule, custody, reserve, or cloud providers; or
- a legal/regulatory change that makes the control mapping materially inaccurate.

## 17. Current public-evidence readiness assessment

This is a drafting assessment of the public repository, not an independent audit opinion.

| Area | Existing basis | Additional evidence required for a production conclusion |
| --- | --- | --- |
| Canonical protocol and deterministic testing | Strong public design and test inputs: canonical schemas, vectors, strict rejection, CI, formal artifacts. | Frozen independent reproduction, deeper adversarial audit, deployment/configuration evidence, and closure of open launch gates. |
| Authorization and delegated authority | Principals, capabilities, APL default deny/forbid precedence, budgets, approvals, and atomic obligations provide a useful control foundation. | End-to-end composition audit, finalized key provenance, recovery, mobile custody, and all production paths. |
| Credentials and privacy | P-021 keeps credentials off-chain and binds issuer/schema/status/freshness; architecture describes selective proofs and data minimization. | Approved KYC/KYB/PEP schemas and issuers, assurance governance, private-predicate implementation/conformance, revocation SLAs, and operating evidence. |
| Native money and fraud prevention | P-090 removes a reusable native mint key and defines constrained issuance; testnet gates address replay, restart, and double mint. | Independent supply proof across every economics path, finalized production consensus, reserve/asset-specific controls where relevant, and external audit. |
| Payment/bridge evidence | P-091 separates provider code from consensus and defines evidence classes and idempotency. | Provider adapters, authenticated ingress, reconciliation, bridge conservation, operational controls, and independent tests. |
| Sanctions, TF, and PF | Protocol primitives can carry scoped verified facts and policies. | No complete public evidence was identified for list governance, screening operations, address analytics, matching, overrides, freeze workflow, or TF/PF monitoring. |
| Travel Rule and self-hosted addresses | Canonical transaction binding and privacy architecture are suitable building blocks. | Secure off-chain message profile, counterparty-CASP controls, exact transfer binding, missing-data workflow, self-hosted controls, retention, and interoperability tests. |
| Transaction monitoring, cases, and FIU reporting | Finalized receipts and deterministic events can support monitoring data. | Complete data pipeline, typologies, models/scenarios, cases, analyst QA, suspicious-activity process, anti-tipping-off controls, and S3 evidence. |
| Privacy and recordkeeping | Architecture states that raw credentials and stable global identifiers remain off-chain. | Formal data inventory, GDPR/DPIA analysis, retention/deletion, confidential evidence system, access testing, and breach response. |
| Stablecoin/issuer assurance | Website and protocol drafts distinguish protocol capability from an issued regulated product. | Legal issuer, authorization, asset definition, redemption terms, reserves/custody, confirmations, reconciliations, disclosures, and issuer audit. |
| Independent audit status | A detailed pre-launch audit scope exists. | The repository expressly states that no security audit has been completed; engagement, remediation, re-review, and publication remain required. |

## 18. Regulatory and standards mapping

This mapping is a baseline for counsel and auditors, not a legal-equivalence table. The register MUST be refreshed for each engagement. The [FATF Recommendations](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/Fatf-recommendations.html) were last updated in June 2026, and virtual-asset implementation continues to evolve, including the [2026 targeted update on virtual assets and VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html).

| Source | Topics mapped by this protocol |
| --- | --- |
| [FATF Recommendations](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/Fatf-recommendations.html) | Risk-based approach; targeted financial sanctions for terrorism and proliferation; CDD; recordkeeping; PEPs; new technologies/virtual assets; payment transparency; internal controls; suspicious-transaction reporting; tipping-off/confidentiality; beneficial ownership. |
| [FATF updated guidance for virtual assets and VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/Guidance-rba-virtual-assets-2021.html) | Activity-based scope, VA/VASP risk, peer-to-peer and self-hosted risk, licensing/registration, stablecoins, Travel Rule, supervision, and information sharing. |
| [FATF virtual-asset red-flag indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html) | Transaction patterns, anonymity/obfuscation, geographic risk, unusual size/frequency, source-of-funds concerns, fraud, sanctions evasion, and other typologies. |
| [FATF 2026 DeFi report](https://www.fatf-gafi.org/en/news/targeted-report-decentralised-finance-2026.html) | Assessment of control or sufficient influence and the application of Recommendation 15 to relevant arrangements. |
| [Regulation (EU) 2023/1113 — Transfer of Funds Regulation](https://eur-lex.europa.eu/eli/reg/2023/1113/oj/eng) | Originator/beneficiary information, secure transmission, missing information, self-hosted addresses, ownership/control assessment over EUR 1,000, restrictive-measures controls, data protection, and recordkeeping. It applies from 30 December 2024. |
| [Regulation (EU) 2023/1114 — MiCA](https://eur-lex.europa.eu/eli/reg/2023/1114/oj/eng) | Crypto-asset issuers, offers/white papers, asset-referenced and e-money tokens, CASP authorization/operation, governance, custody, conflicts, and disclosures. |
| [Regulation (EU) 2022/2554 — DORA](https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng) | ICT risk management, incident reporting, operational-resilience testing, ICT third-party risk, and information sharing for in-scope financial entities, including authorized CASPs and issuers of asset-referenced tokens. It applies from 17 January 2025. |
| [Regulation (EU) 2024/1624 — AML Regulation](https://eur-lex.europa.eu/eli/reg/2024/1624/oj/eng) | Obliged entities, business-wide and customer risk, CDD/KYB/beneficial owners, inability to complete CDD, PEPs, source of wealth/funds, self-hosted-address risk, suspicious reporting, data protection, and records. Most provisions apply from 10 July 2027; this protocol treats them as readiness requirements where relevant. |
| [Directive (EU) 2024/1640 — AMLD6](https://eur-lex.europa.eu/eli/dir/2024/1640/oj/eng) | National AML/CFT mechanisms, FIUs, supervision, registers, and implementation context. National transposition and local law remain essential. |
| [GDPR — Regulation (EU) 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng) | Lawfulness, purpose limitation, minimization, accuracy, security, rights, DPIA, processors, international transfers, breach response, and automated decisions. |
| [UN Security Council Consolidated List](https://main.un.org/securitycouncil/en/content/un-sc-consolidated-list) | Dynamic UN targeted-financial-sanctions screening input. |
| [EU sanctions policy and regimes](https://www.consilium.europa.eu/en/topics/sanctions/) | EU restrictive measures, including terrorism- and proliferation-related regimes. Exact operative lists and national implementation must be identified by counsel/control owners. |

For Sweden or any other specific market, the engagement MUST add a national annex covering licensing/registration, supervisory expectations, FIU reporting, sanctions implementation, consumer protection, tax, privacy, and any stricter local requirements.

## 19. Evidence-manifest template

The public repository SHOULD contain a machine-readable evidence manifest. Confidential items may use controlled locators and non-enumerable commitments.

```json
{
  "schema": "activechain-audit-evidence-manifest-v1",
  "audit_id": "AC-YYYY-NNN",
  "subject": {
    "name": "<service-or-module>",
    "legal_entity": "<entity>",
    "role": "<developer|operator|CASP|issuer|custodian|bridge>",
    "jurisdictions": ["<ISO-3166 code>"],
    "modules": ["CORE", "IDENTITY"]
  },
  "freeze": {
    "repository": "https://github.com/advatar/ActiveChain",
    "commit": "<40-character-sha>",
    "source_sha256": "<sha256>",
    "release_tag": "<signed-tag>",
    "genesis_sha256": "<sha256>",
    "configuration_sha256": "<sha256>",
    "sbom_sha256": "<sha256>"
  },
  "period": {
    "start": "<RFC3339>",
    "end": "<RFC3339>"
  },
  "evidence": [
    {
      "id": "E-0001",
      "controls": ["CORE-01"],
      "tests": ["T-CORE-001"],
      "grade": "E4",
      "title": "Independent canonical-vector reproduction",
      "public_url": "<commit-pinned-url-or-null>",
      "confidential_locator": "<authorized-locator-or-null>",
      "sha256": "<sha256>",
      "created_at": "<RFC3339>",
      "collected_at": "<RFC3339>",
      "owner": "<owner>",
      "result": "pass|fail|exception",
      "limitations": "<text>",
      "classification": "public|confidential|restricted",
      "retention_until": "<date>"
    }
  ],
  "manifest_signature": "<auditor-signature>"
}
```

## 20. Test-record template

```markdown
# Test <TEST-ID>: <title>

- Audit ID:
- Frozen commit/release/configuration:
- Control IDs:
- Tester and independent reviewer:
- Date/time and trusted time source:
- Environment and tool versions:
- Preconditions:
- Threat or failure hypothesis:
- Input/vector hashes:
- Procedure:
- Expected result:
- Actual result:
- Output/log/artifact hashes:
- Evidence IDs:
- Deviations and limitations:
- Result: Pass / Fail / Blocked
- Finding ID, if any:
- Retest record:
```

## 21. Public audit-report template

```markdown
# ActiveChain independent assurance report — <audit subject>

## Opinion
<Pass / Pass with limitations / Fail / Not examined by module>

## Audit subject and accountable entities
<roles, services, assets, jurisdictions, control owners>

## Scope and exclusions
<modules, systems, providers, period, exclusions and reason>

## Frozen artifacts
<full commit, tag, source/binary/config/genesis/policy hashes>

## Assurance stage
<S0 / S1 / S2 / S3>

## Independence and competence
<auditor, specialists, conflicts and safeguards>

## Criteria
<link to this protocol version and jurisdiction annexes>

## Methods
<code review, reproduction, formal review, negative testing, sampling, confirmations>

## Results by control domain
<summary table>

## Findings and remediation
<public findings, severity, status, retest>

## Limitations
<technical, operational, legal, data, period and provider limitations>

## Evidence
<link to signed evidence manifest; identify confidential annex without revealing contents>

## Validity and reassessment triggers
<expiry and material-change conditions>

## Signatures
<auditor and report date>
```

## 22. Maintenance of this protocol

Changes to this protocol SHOULD use pull requests with:

- a reason and risk analysis;
- links to changed legal, regulatory, technical, or threat information;
- control/test additions, removals, or changed pass criteria;
- review by security, financial-crime, privacy, and legal specialists as applicable;
- a semantic document version; and
- a changelog identifying whether existing audit conclusions require reassessment.

The protocol SHOULD be reviewed at least annually and promptly after material changes to FATF standards, EU or national law, major virtual-asset typologies, ActiveChain architecture, cryptographic assumptions, asset issuance, or regulated activities.

## 23. Disclaimer

This document is a technical and control-assurance framework. It is not legal advice, a licence application, a regulator's approval, an audit report, or a guarantee that crime, fraud, money laundering, terrorist financing, proliferation financing, sanctions evasion, loss, or security failure cannot occur. Qualified counsel and competent independent auditors must tailor the scope to the actual entities, activities, assets, customers, and jurisdictions.
