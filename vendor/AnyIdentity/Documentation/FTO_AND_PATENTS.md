# AnyIdentity: preliminary freedom-to-operate and patentability investigation

**Research date:** 9 September 2026. **Scope:** the supplied BRIEF1.md and PATENT.md and the accompanying AnyIdentity 0.1 reference implementation. Default markets: United States, Europe including Sweden, and United Kingdom. No actual filing date, inventor history, product deployment geography or patent licences were supplied.

## Finding

**This investigation does not establish freedom to operate. The briefs' favourable broad patentability ratings are not supported by the wider prior art found.** Multi-issuer credentials, persistent key-controlled identities, pairwise pseudonyms, credential-derived private identities and constrained delegation have substantial earlier disclosures. A particular new protocol may still support narrow claims, but “identity convergence first, delegation second” is not itself an established inventive distinction.

There are concrete differences between this implementation and several reviewed independent claims. Those differences support further claim analysis, not a non-infringement opinion. The full proposed product, especially anonymous identity-assurance transfer and native government-credential adapters, has a larger exposure than the implemented core.

This is a technical research memorandum for counsel, **not a legal clearance opinion**. Patentability and FTO are different: owning a patent does not give permission to practise inventions covered by someone else's patent. [USPTO, managing a patent](https://www.uspto.gov/patents/basics/manage).

## What was investigated

The implementation signs normalized attestations binding a holder-controlled Ed25519 key to a persistent authority identifier. A verifier evaluates externally trusted roots, independent issuer groups, required claims, assurance levels, freshness and status. It supports current-key/new-key rotation approval, preconfigured recovery-key quorum approval, deterministic per-audience keys, bounded delegation chains and signed actions.

The code does **not** verify passports/mDL/EUDI/UK credentials, establish biological same-person equality across roots, produce anonymous credential proofs, preserve derived keys after loss of the derivation secret, or implement a distributed continuity/revocation service. These distinctions are material to both technical readiness and the claim mapping.

The search used identifiers from both briefs, cross-issuer/persistent-identity/pairwise/recovery/delegation queries, and backward/family references from relevant documents. The records below reproduce patent disclosures and claims on Google Patents or Justia. Bibliographic and status labels are provisional; Google expressly disclaims legal-status accuracy. Public office guidance and original standards/papers were also checked. See [search record](PATENT_SEARCH_LOG.md).

## Audit of the supplied citations

| Citation in briefs | Result as of research date |
|---|---|
| GOV.UK Wallet issuance documentation | Retrieved. Describes holder-key proof during issuance. Supports the conclusion that credential-to-key binding is established practice. [Issuance documentation](https://docs.wallet.service.gov.uk/issue-credentials/credential/) |
| EU 2026/1731 | The EU Publications Office indexes this regulation. The supplied EUR-Lex URL and alternative ELI route returned no usable substantive text in this session. Its detailed wallet-key-attestation requirements were **not independently verified here**. Do not quote those requirements from the brief as checked law. [EU Publications Office record](https://op.europa.eu/pl/publication-detail/-/publication/802ddc72-856b-11f1-bf5e-01aa75ed71a1/language-et) |
| WO2023022584A1; EP1886437A1 | Retrieved. Relevant to document-derived identity and e-passport authentication; they do not establish monopoly over every passport adapter. See family triage below. |
| WO2024116104A1; WO2022256121A1 | Retrieved. Both WO records display ceased status; that alone does not dispose of national rights. Claim mechanisms and national-family leads are below. |
| US12,671,588 | Exact title and claims retrieved on Justia, which reports a 30 June 2026 grant. Google B1 URL and the attempted USPTO PDF endpoint failed. Treat existence, grant text and current enforceability as requiring official corroboration before counsel relies on it. |
| US20260162161 | Retrieved as an application published 11 June 2026. Its page links to **US12,705,654**, reported granted 11 August 2026. The brief's “application” description is therefore potentially outdated; review the grant. [Application record](https://patents.justia.com/patent/20260162161), [reported grant](https://patents.justia.com/patent/12705654) |
| US12,346,424 | Retrieved granted US claims, with a 1 July 2025 publication. Its DID-registry exchange matters; the title alone is much broader than claim 1. |
| arXiv 2506.00262 | Retrieved as *Compact and Selective Disclosure for Verifiable Credentials*, 2025. Selective-disclosure prior art; not a patent clearance source. [Paper](https://arxiv.org/abs/2506.00262) |
| arXiv 2605.11487 | Retrieved as *Digital Identity for Agentic Systems: Toward a Portable Authorization Standard for Autonomous Agents*, 2026. Relevant published architecture, not proof of commercial necessity or patent exclusivity. [Paper](https://arxiv.org/abs/2605.11487) |
| SSRN 6920081 | Search retrieved the original SSRN abstract: Avik Nandi, written 10 June 2026 and posted 25 June 2026. The initial direct open failed. Its abstract describes agent identity and delegated payment authority; the full paper was not reviewed. [SSRN record](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6920081) |

## Patent families and implementation mapping

“Priority” below is the earliest date shown by the reviewed record, not a conclusion that every claim is entitled to it. “Reported active” is a database label, not verified enforceability. The mapping is my technical inference from the cited claims and the source code. It is not a complete legal element chart or an equivalents analysis.

### P1 — Microsoft: binding derived identifiers to verified claims

**US11245524B2**, priority 18 June 2019, granted 8 February 2022; reported active. Family includes **EP3984164B1**, reported granted 10 December 2025, and CN114008971B.

US claim 1 includes a derived decentralized identifier and a claim-binding association structure containing a MAC. Claim 12 separately specifies deriving a private key and a two-function construction generating a seed and association structure. The verified claim includes that structure. This is particularly close prior art to the brief's derived-authority layer.

`IdentityKey.pairwiseKey` derives a key, but the package neither constructs that disclosed claim-binding association nor places it in issuer claims. **HKDF internally using HMAC is not, by itself, the claimed association structure.** Adding a privacy-preserving credential-binding protocol could change this assessment. Renaming a DID to “authority” would not be a reliable distinction.

**Review priority: high**, especially before implementing inherited pairwise assurance. [US claims](https://patents.google.com/patent/US11245524B2/en), [EP member](https://patents.google.com/patent/EP3984164B1/en).

### P2 — HID: aggregated credentials with assurance levels

**US12050679B2**, priority 1 April 2019, granted 30 July 2024; reported active. The family table identifies **EP3932037B1**; that EP document did not open, so its granted scope is unresolved.

Claim 1 specifies issuer data included by reference using a URI containing issuer address, source-package identifier and source-package hash. Independent claims 10 and 15 also concern response data from a package containing a referenced element; claim 15 uses requested minimum confidence and issuer relevance.

`protocol::assess` evaluates complete signed evidence locally. It does not construct the referenced-package/URI mechanism or retrieve nested source packages. Nevertheless, the description and assurance-dependent claims materially weaken novelty assertions around “compositional assurance” alone. Implementing reference-based credential aggregation needs a fresh chart.

**Review priority: high for the full architecture; identifiable differences in the current core.** [US record and claims](https://patents.google.com/patent/US12050679B2/en).

### P3 — Nokia: linking credentials across identity providers

**US20140245412A1**, priority 16 May 2011, published 28 August 2014; reported abandoned. The application describes credentials from multiple identity providers and common identifying attributes, including pseudonyms. Claims 1 and 4–8 are particularly relevant to the broad convergence proposition.

Current code accumulates signed evidence bound to a common key/authority. The older disclosure is therefore a significant novelty/obviousness lead. An abandoned US application is not itself an enforceable granted US claim; foreign members, descendants and the abandonment record were not exhaustively checked.

**Review priority: high for patentability; no live US right established from this application record.** [Record and claims](https://patents.google.com/patent/US20140245412A1/en).

### P4 — Google: anonymous/pseudonymous access

**US9154306B2**, priority 23 June 2009, granted 6 October 2015; reported active. Parent **US8281149B2**, granted 2 October 2012, is reported expired for fees in the family table; official maintenance/revival checks remain necessary.

The active child's independent claims concern an issuer-provided token transformed into an unlinkable representation and verification/access flows. Its disclosure includes site pseudonyms reproducible from fixed master key material. That disclosure directly undermines “master authority → pairwise keys” as a broad novelty proposition.

The current code derives keys locally but has no blinded/transformed issuer access token. Parent claims 11 and 23 discuss pseudonyms but depend on broader access-token claims. Do not mistake a description or dependent limitation for a standalone exclusion right.

**Review priority: high before anonymous credential work; current token-transformation elements absent.** [Child and family status](https://patents.google.com/patent/US9154306B2/en), [parent claims](https://patents.justia.com/patent/8281149).

### P5 — Microsoft: verifiable pairwise claims

**US12401509B2**, priority 30 January 2020, granted 26 August 2025; reported active. Family: WO2021154999A1, LU101620B1, **EP4070212A1** and CN115053217A.

US independent claims 1 and 14 require requests with encrypted portions, verification through decryption, separately encrypting claims for respective verifier public keys, and use of the same subject DID across those issuances. They do not simply claim every per-audience signing key.

`derive` uses HKDF and the enrollment flow verifies signatures. There is no encrypted issuance-request workflow or verifier-only claim encryption. The EP application was retrieved, but national scope/status cannot be inferred from the US grant.

**Review priority: medium for current code, high if adding encrypted pairwise claim issuance.** [US grant](https://patents.google.com/patent/US12401509B2/en), [EP application](https://patents.google.com/patent/EP4070212A1/en).

### P6 — Accreditrust: interdependent credential validation

**US11587096B2**, priority 14 October 2015, granted 21 February 2023; reported active. The record also identifies **US11989738B2**, not fully charted here.

Claim 1 concerns linked-data credential collections with collection status and digital signing, including status consequences when a constituent fails validation. The description includes professional credentials and portability across identity providers.

`assess` calculates a relying-party decision over independent signed attestations; it does not issue a signed linked-data credential collection with the claimed collection lifecycle. The older combination of credentials and policy validation remains a relevant patentability obstacle. The additional grant deserves counsel's review.

**Review priority: medium/high.** [Record, claim 1 and related grant](https://patents.google.com/patent/US11587096B2/en).

### P7 — Workday: split-key wallet recovery

**EP4154153B1**, priority 21 May 2020, granted 1 October 2025; reported active.

Independent claims include recovering a user private key using shares obtained via credential-issuing and trusted organizations, and corresponding split/encrypted-share storage mechanisms. Claim 1 also specifies discovery of a trusted organization via the credential issuer.

`apply_transition` changes authority control to a fresh key after independent signatures by pinned guardians and the replacement key. It neither reconstructs the old private key nor splits/recombines recovery encryption material. Exporting/importing a seed is a separate manual backup operation, without the disclosed share workflow.

**Review priority: medium for current recovery; high if introducing identity-provider-mediated secret reconstruction.** EPO Register requests failed. Sweden/UK validation, unitary effect, opposition and national renewal status were not confirmed. [EP grant](https://patents.google.com/patent/EP4154153B1/en).

### P8 — PCI Global: delegate decentralised identities

**WO2024116104A1**, priority 30 November 2022, published 6 June 2024; WO record reported ceased. Its family table showed WO only; this is not proof that no national filing exists.

The disclosed/claimed delegation exchanges involve a separate authenticated channel and remotely using the first party's identity/private-key capability from the delegate's device, with the private key remaining on the first device.

AnyIdentity issues a signed capability to the agent's own key. Later requests are signed locally by that key; the agent does not remotely invoke the person's signer. This is a substantive implementation distinction worth confirming against national claims if found.

**Review priority: medium; national enforceable rights unresolved.** [WO disclosure, claims and family](https://patents.google.com/patent/WO2024116104A1/en).

### P9 — ETRI: delegated credentials with a DID registry

**US12346424B2**, priority 29 September 2021, granted 1 July 2025; reported active.

Claim 1 requires wallets exchanging a new DID document, a registry duplicate check and transmission of delegated credentials together with previous/original credentials and registration requests. It is considerably more specific than “delegation chains”.

`verify_action` processes signatures and parent-envelope digests against a pinned public key. There is no DID registry, DID-document issuance/duplicate-check flow, or mandatory transmission of an original government credential. Additional independent apparatus claims and foreign rights need a complete chart.

**Review priority: medium for current code; higher for DID-registry integration.** [Granted claims](https://patents.google.com/patent/US12346424B2/en).

### P10 — Microsoft: endorsement credential

**WO2022256121A1**, priority 31 May 2021. US member **US20220385475A1** is reported abandoned; **EP4348915A1** reported withdrawn; WO ceased. These are secondary status leads.

WO claim 1 specifies an endorsement claim from a trusted first entity embedded in a second claim specifying a service on behalf of a fourth entity, with DID-key verification by a third entity. Current delegation envelopes contain parent digests and explicit permissions rather than that endorsement issuance workflow.

**Review priority: lower live-right priority on the retrieved status, substantial prior-art relevance.** Do not infer freedom to operate merely from the WO status; verify the identified national files and descendants. [Claims and national family table](https://patents.google.com/patent/WO2022256121A1/en).

### P11 — Crown and Cross: integrated agent-control architecture

**US12671588**, Justia reports filing 3 March 2026 and grant 30 June 2026, assignee The Crown and the Cross LLC, application 19/554,930. Official grant/status not corroborated.

Independent claims 1, 15 and 20 describe an integrated combination extending from identity-bound authorization into connector-descriptor checks, constrained tool execution, a context firewall, linked receipts, an append-only transparency log and offline lineage verification.

The package signs actions/delegations but does not execute connectors, segregate model instructions/tool output, generate the specified receipt lineage, or register transparency-log proofs. Those missing elements matter. Integrating this package into ARK or an agent-execution platform could alter the analysis substantially.

**Review priority: verify record first; high at complete agent-platform integration.** [Reported grant and claims](https://patents.justia.com/patent/12671588).

### P12 — Delegated access in intermittent/offline environments

**US20260162161 → reported US12705654**, claimed provisional priority 10 December 2024. Justia reports grant 11 August 2026, application 19/407,896. Inventors: Jesús Alejandro Cárdenes Cabré, Madjid Aoudia and Jeremy Taylor. Official grant/ownership/status remain to be confirmed.

Grant claim 1 includes a service-provider agent receiving a consumer-agent request, identifying a verification program based on the action, validating a provider-signed credential containing the consumer-agent key, verifying the request and authorizing execution. Independent claim 15 concerns the consumer-agent side of provider-signed credential use.

Current delegations are person-signed, not provider-issued authorizations; no transaction is executed. A provider could deploy the generic primitives in a closer arrangement, so the library's configurability matters. Offline checking alone is not a sufficient exclusion or infringement test.

**Review priority: high before provider-issued agent authorization.** [Application](https://patents.justia.com/patent/20260162161), [reported granted claims](https://patents.justia.com/patent/12705654).

### P13 — Passport-related families from BRIEF1.md

**WO2023022584A1**, priority 16 August 2021, publication 23 February 2023, describes decentralising identification from documents into digital credentials, with person verification. A detailed adapter chart and national-family status investigation remain necessary. Current core receives already normalized signed evidence and performs no passport scanning or facial matching. [WO record](https://patents.google.com/patent/WO2023022584A1/en).

**EP1886437A1**, priority 20 May 2005, publication 13 February 2008, concerns privacy-enhanced e-passport authentication. It is a dated publication lead, not evidence that all e-passport implementations are blocked. Current core performs no chip/terminal authentication. The record identifies EP1886437B1 and a divisional EP2490366B1, and reports lifetime expiry on 23 May 2026. Confirm term and territorial status before relying on expiry for a chosen NFC protocol. [EP publication](https://patents.google.com/patent/EP1886437A1/en).

## Earlier non-patent disclosures

These documents matter even where no enforceable patent has been identified. Dates of particular versions and enabling content must be matched to any eventual filing date.

| Document | Relevance to the proposed claims |
|---|---|
| [SPKI Certificate Theory, RFC 2693 (1999)](https://www.rfc-editor.org/rfc/rfc2693) | Authorization associated with keys, delegation, authorization intersections, thresholds and validity. Strong early context for issuer-independent cryptographic authority and attenuation. |
| [Camenisch–Lysyanskaya, EUROCRYPT 2001](https://www.iacr.org/archive/eurocrypt2001/20450093.pdf) | Anonymous credential systems across organizations with unlinkable use. The high-level combination of credentials and private pseudonymous authorization is old. |
| [OpenID Connect Core §8.1](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg) | Pairwise subject identifiers with sector-specific calculation; the base specification dates to 2014, while the retrieved page includes errata. Useful prior art for the privacy objective, even though identifiers are not necessarily signing keys. |
| [Macaroons, NDSS 2014](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/) | Decentralized, attenuated authorization with contextual caveats. Applying constrained delegation to an AI agent does not itself distinguish the underlying technique. |
| [KERI, first submitted July 2019](https://arxiv.org/abs/1907.02143) | Persistent self-certifying identifiers, key events, rotation and witnessed continuity. Analyse version history before asserting any precise feature was in the earliest version. |
| [W3C DID Core, 19 July 2022 Recommendation](https://www.w3.org/TR/2022/REC-did-core-20220719/) | Controller-managed identifiers, verification methods, rotation, authentication and capability-delegation relationships. “More than another DID” needs a mechanism, not different terminology. |
| [LinkDID, first submitted July 2023](https://arxiv.org/abs/2307.14679) | Explicitly combines privacy, selective disclosure and key recovery. A particularly relevant combination reference; not treated here as anticipating every AnyIdentity element. |
| [OPPID, 2024 preprint](https://eprint.iacr.org/2024/1124.pdf) | Oblivious pairwise pseudonyms and identity-provider privacy; challenges any broad claim to pairwise identity with hidden relying-party relationships. |

## Reassessment of patentability

| Proposed proposition | Assessment from this investigation |
|---|---|
| Credential bound to a person-controlled key | Established technique. Not a persuasive broad invention claim. |
| Heterogeneous roots converge on a common authority | Significant older credential-linking and collection disclosures. Exact same-person/security mechanism might matter; no broad novelty finding. |
| Authority persists through credential renewal | Persistent key identity plus renewed evidence is a natural combination. A concrete new continuity mechanism would need to distinguish DID/KERI and recovery work. |
| Assurance composes across independent roots | HID and Accreditrust disclosures are close; independence policy alone has not been established as inventive. |
| Pairwise identity derived from the authority | Directly adjacent Microsoft patents and older pseudonym systems. High prior-art density. |
| Identity-backed agent delegation | SPKI/macaroons and newer agent patents undermine novelty at the stated level of generality. |
| All of these together | No single reviewed document was established to anticipate every element of a precisely defined claim. **That is not a positive novelty or inventive-step conclusion.** A predictable combination of known techniques can still be unpatentable. |

The actual unsolved technical questions are more useful than the architecture diagram: how to prevent two people pooling credentials on one key; how to prove lineage after recovery without exposing a global identifier; how to make hidden revocation/epoch state current without correlation; and how to attenuate agent permissions while preserving those privacy guarantees.

The current reference implementation does not solve those problems cryptographically. It establishes shared key control and trusts attestors' identity-binding assertions. It should not be presented as a completed reduction to practice of an unlinkable, same-person convergence invention.

A candidate narrow disclosure would need an explicit enrollment transcript, threat model, same-person proof construction, issuer-independence model, recovery authorization and fork-resolution rule, privacy-preserving status mechanism, derivation/proof equations and failure cases. Measure concrete security or computational improvements against the closest alternatives. No claim of novelty is made for that research direction.

US software claims must address eligibility as well as novelty/non-obviousness and disclosure requirements; adding cryptographic vocabulary does not automatically resolve an abstract-idea objection. [USPTO MPEP §2106](https://www.uspto.gov/web/offices/pac/mpep/s2106.html). In Europe, the technical problem and technical effect contributing to inventive step need to be identified. [EPO digital-invention guidance](https://www.epo.org/en/news-events/in-focus/digital-innovations/patentability-digital-inventions).

## Territorial FTO and unresolved register work

| Market | What this research supports | Still required for a clearance decision |
|---|---|---|
| United States | A prioritized set of grants/application leads and code-level claim distinctions. | Obtain official issued claims and prosecution histories; verify assignments, maintenance, terminal disclaimers, continuations, reissues, PTAB/court changes, and any relevant licences. Confirm both reported 2026 grants. |
| Sweden / other EU states | Specific EP leads: EP3984164B1, EP4154153B1, reported EP3932037B1; application EP4070212A1. | Check EPO files, unitary effect, national validation/lapse/renewals and surviving national claims, including Sweden. “EU patent” is not a substitute for territorial analysis. |
| United Kingdom | Same EP families can be relevant through UK validation, plus possible GB filings. | Check UK IPO national records, validation and fee status, and GB family/continuation leads. UK coverage must not be inferred from an EU/UP record. |

EPO Register requests for the principal recovery and derived-identifier families failed in this session. No Swedish or UK case-specific register results were obtained. This limitation is why the report does not label any market cleared. The EPO describes its register and links to national post-grant records as the appropriate route for procedural/status checks. [EPO Register](https://www.epo.org/en/searching-for-patents/legal/register), [Federated Register](https://www.epo.org/en/service-support/faq/searching-patents/european-patent-register-and-federated-register/federated-0).

Pending and unpublished applications create residual uncertainty. European applications are generally published 18 months after filing/priority; absence from today's search is not evidence of absence. [EPO publication guidance](https://register.epo.org/help?lng=en&topic=publicationdate). FTO scope also depends on where implementations are made, used, sold or supplied and which entity performs each claimed step. A package-only comparison is insufficient for an integrated commercial deployment. [Finnish Patent Office FTO guidance](https://www.prh.fi/en/intellectualpropertyrights/patentit/theabcofpatenting/servicesanddatabases/searchservices/freedomtooperatereview.html).

## Recommended disposition

1. **Use this implementation as an internal reference and review artifact.** Do not label the protocol patent-free or the full brief implemented. The implementation boundaries are documented in [PROTOCOL.md](PROTOCOL.md).
2. **Commission targeted US/EP/SE/UK counsel review of P1, P2, P4, P7 and the two reported 2026 grants**, followed by P5/P6/P9 and actual adapter families. Provide this report, the exact source revision, deployment flows and any existing licences. Include the identified uncharted related grants.
3. **Prepare a human-authored invention history and enabling disclosure before deciding what to file.** Preserve dates, contributors, earlier prototypes and disclosures. The supplied notes are not evidence of priority. Broad concept valuation and inevitable-incumbent-resistance predictions in PATENT.md are not substantiated by this search.
4. **Make any public-release decision together with the filing strategy.** An enabling public disclosure can affect European novelty. Do not rely on a presumed general grace period. [EPO novelty guidance](https://www.epo.org/en/new-to-patents/is-it-patentable).
5. **Treat open-source copyright licensing and patent licensing separately.** A chosen RF/FRAND policy for patents you own cannot license third-party patents. No patent grant, standards commitment or public-source licence is adopted by this implementation or memorandum. Dependency notices are tracked separately.

**Decision supported today:** proceed with technically bounded development and a focused claim/status investigation. **Decisions not supported:** commercial FTO clearance, confident broad patentability, or a patent valuation.
