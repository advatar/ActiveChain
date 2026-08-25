# Kenya VASP and stablecoin control register v1

Status: normative activation catalogue; deployment approval required.

Source snapshot: *The Virtual Asset Service Providers Regulations, 2026*, Legal Notice No. 134,
Kenya Gazette Supplement No. 185 (22 July 2026), made under the Virtual Asset Service Providers
Act (No. 20 of 2025). A deployment records a digest of the exact authoritative source reviewed;
this register is not legal advice and does not replace the Act, Regulations, regulator directions,
AML/CFT law, sanctions law, data-protection law, or qualified Kenyan counsel.

`KenyaRegulatedProfileV1` fails closed unless every activity-required control family below is set,
every common approval/policy commitment is nonzero, the operator is named, and the activation
window is bounded. Stablecoin issuance additionally requires nonzero reserve, custody, redemption,
and approved-white-paper commitments. A commitment proves only that the operator bound a signed
versioned artefact; it does not prove its truth, execution, licence status, or regulatory approval.

The machine-readable [Kenya regime pack](packs/ke.vasp-regime.2026.json) pins the operating-model
facts reviewed in *Which Model Is Tanzania Actually Copying?* (20 August 2026), SHA-256
`cd4da651c0e3d367f2b200cab864d57add595e2bb59aa676b9e7063483cb3f30`. The comparison is an internal
cross-check, not authoritative law; each deployment must still commit the exact official sources
reviewed by qualified Kenyan counsel.

## Licensed activity model

| Activity | Supervisor | Minimum capital (KES) |
|---|---|---:|
| Wallet provision | CBK | 150,000,000 |
| Exchange operation | CMA | 100,000,000 |
| Payment processing | CBK | 10,000,000 |
| Brokerage | CMA | 10,000,000 |
| Investment advisory | CMA | Nil |
| Asset management | CMA | 20,000,000 |
| ICO issuance | CMA | 20,000,000 |
| Real-world-asset tokenisation | CMA | 10,000,000 |
| Token issuance platform | CMA | 20,000,000 |
| Stablecoin issuance | CBK | 300,000,000 |

One licence may cover multiple activities at the relevant regulator's discretion. Applicants are
companies limited by shares; a foreign company must be registered in Kenya. A physical Kenyan
office and local bank account are required, and a natural person cannot be the VASP applicant.
The exact board size is intentionally not encoded because the reviewed comparison did not confirm
it. The Act's application clause and licensing prohibition are represented separately: the former
addresses services `in Kenya`, while the latter prohibits unlicensed services `in or from Kenya`.
The pack does not invent an express nonresident-provider targeting test. It also records that
virtual assets are not legal tender and the 4 November 2026 deadline reported for existing
providers.

CBK supervises wallet provision, payment processing, and stablecoin issuance. CMA supervises
exchange operation, brokerage, investment advisory, asset management, ICO issuance, real-world-
asset tokenisation, and token issuance platforms. These allocations and capital amounts classify
the licence evidence required for an operator; they do not grant a licence through repository
configuration.

The pack preserves consultation provenance without treating drafts as current obligations:
stablecoin minimum capital moved from KES 500 million to KES 300 million, investment-adviser
capital moved from KES 2.5 million to nil, and the draft 33.3% single-holder cap was replaced by a
notify-below-10% / approve-above-10% ownership-change regime. The transition likewise moved from
six months in the published Bill to twelve months in the enacted framework. Only the final fields
classify deployment evidence.

## Canonical control families

| Bit | Control family | Regulations | Required evidence and enforcement boundary |
|---:|---|---|---|
| 0 | Licensing | 5-16, 61 | Applicable licence/authorization, licensed activities, conditions, fees, commencement, renewal, changes, assignment and revocation are verified by the operator against the authority record; admission fails closed on absent/expired evidence. |
| 1 | Ongoing obligations | 17-24, 31, 34-38 | Ongoing licence compliance, competent resources, business/default rules, continuity, transaction information, employee/consumer disclosures, point-of-service information, confirmations, allocation, off-market reporting and inspection readiness have named owners and evidence. |
| 2 | CDD, AML and transaction information | 22, 25-27, 32-33 | Pre-onboarding and pre-listing due diligence, customer suitability/information, transaction data, monitoring, records and regulator/FIU reporting execute off-chain; only bounded decisions and commitments enter protocol evidence. |
| 3 | Governance and risk | 39-45 | Compliance officer, risk framework, board composition/duties, CEO, finance and internal audit roles are approved and periodically evidenced. |
| 4 | Capital, audit and reporting | 85-95 | Activity-specific capital/liquidity, truthful capital position, permitted use of funds, insurance, accounting, external audit, periodic reports and financial year are monitored outside consensus. |
| 5 | Cybersecurity and continuity | 21, 96-100 | Tested continuity/incident response, cybersecurity strategy, systems/controls, independent audit and incident/risk reporting bind current evidence and expiry. |
| 6 | Asset safekeeping | 66, 101-107 | Wallet duties, segregation/safeguarding, consumer agreements, custody controls, third-party-claim protection, books and reconciliation are provider-operated and independently evidenced. |
| 7 | Consumer protection | 24-25, 31, 102-111 | Fair disclosures, suitability, service terms, asset protection, risk understanding, complaints and care processes are versioned and reviewable. |
| 8 | Market conduct | 19-20, 30, 35-37, 108-122 | Proper/fair markets, conflicts, order priority/allocation, off-market reporting, conduct standards and controls against insider dealing, manipulation, false trading, inducement, front-running, churning and cold calling are monitored. |
| 9 | Advertising | 54-56, 69, 81, 123-133 | Approval/prohibition checks, fair and non-misleading content, performance/cost/risk disclosures, accountable publisher and internet/third-party controls apply before publication; advertisements are retained. |
| 10 | Freezing and seizure | 134-141 | Authentic orders, scope, approvals, custody, value preservation, uninvolved-consumer protection, release/appeal and complete audit trails are enforced by the licensed operator, never by a universal validator power. |
| 11 | Enforcement and exit | 46-48, 142-151 | Intervention/statutory management, sanctions, penalty recovery, forum process, notice/appeal and voluntary/involuntary liquidation have fail-closed suspension and orderly-exit procedures. |
| 12 | Records and regulator access | 26-29, 38, 59, 89-95, 107, 133 | Required registers, ownership changes, accounting/transaction/advertising records, reports, inspections and lawful authority access are retained under Kenyan retention and privacy rules off-chain. |
| 13 | Conflicts and outsourcing | 28-30, 79, 113 | Interests/ownership, conflicts, personal transactions and outsourcing due diligence, contracts, oversight, access, continuity and exit controls are approved and evidenced. |
| 14 | Stablecoin white paper | 67-70, 73-74 | Central Bank licence/approval evidence, complete and approved white paper, publication/modification controls, offer/admission conditions and issuer liability are bound to the exact asset and revision. |
| 15 | Stablecoin issuance and redemption | 71-72, 78, 80-81 | Holder claim, par issuance, redemption at any time, stated terms, no interest, ongoing holder information and compliant marketing are asset-bound; mint/redeem policies fail closed when inactive. |
| 16 | Stablecoin reserves and custody | 67-68, 73, 75-77 | Reserve composition/value, segregation, custody, investment, liquidity and reconciliation policies bind the asset; reserve sufficiency remains independently attested rather than inferred by consensus. |
| 17 | Stablecoin audit, reporting and halt | 82-84 | Independent audits/reviews, reports, holder/regulator disclosures, delisting or issuance halt and issuer reporting have thresholds, owners, deadlines and evidence commitments. |

Bits 0-13 (`0x00003fff`) are mandatory for a Kenya VASP activation. Bits 0-17
(`0x0003ffff`) are mandatory for a Kenya stablecoin-issuer activation.

## Tokenization, ICO and exchange-specific overlays

Regulations 49-65 govern ICO approval, white papers, advertising, registers, listings and
tokenized real-world assets. An operator performing those activities must select a separate signed
activity overlay in addition to the VASP baseline. The Kenya VASP baseline cannot be interpreted
as approval to offer an ICO, operate an exchange/token issuance platform, tokenize real-world
assets, or list a stablecoin. Regulation 60's stablecoin listing condition requires the exchange to
verify Central Bank approval and a duly licensed issuer before listing.

## Deployment activation checklist

1. Identify the Kenyan legal entity, beneficial/control owners, exact services, assets, customers,
   counterparties, data roles and outsourced providers in the signed role/jurisdiction matrix.
2. Obtain qualified Kenyan counsel's signed applicability and control assessment against the exact
   source snapshot and all other applicable law.
3. Record the relevant authority's independently verified licence/approval, permitted activities,
   conditions, issue/expiry dates and status source; never encode a literal `REQUIRED` placeholder.
4. Approve every policy/control artefact represented by the canonical commitments, configure the
   operator services, and complete negative tests and independent review.
5. For stablecoins, bind the exact `AssetId`, approved white paper, reserve/custodian accounts and
   agreements, investment policy, par issuance/redemption policy, no-interest control, audits,
   reports and halt/delisting plan.
6. Activate only for a nonzero bounded height window. Revocation, expiry, source change, material
   control change, adverse audit, reserve exception or regulator direction suspends admission until
   a newly approved revision is committed.
7. Retain raw identity, screening, Travel Rule, reserve, case, order and regulatory-reporting data
   in authorized off-chain systems. Publish only non-enumerable commitments and safe outcomes.
