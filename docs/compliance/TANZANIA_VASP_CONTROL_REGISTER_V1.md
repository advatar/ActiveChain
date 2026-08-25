# Tanzania proposed VASP control register v1

Status: proposal-only comparison register; activation prohibited.

Source snapshot: *Which Model Is Tanzania Actually Copying?* (20 August 2026), reviewed from
`Tanzania_vs_Kenya_VASP_Model_Comparison.docx` with SHA-256
`cd4da651c0e3d367f2b200cab864d57add595e2bb59aa676b9e7063483cb3f30`. The comparison describes
a Tanzanian concept note and proposed legislative timetable, not enacted VASP legislation or
gazetted operative regulations. This register is not legal advice or regulatory authorization.

The machine-readable [Tanzania proposal pack](packs/tz.vasp-proposal.2026.json) deliberately has
`activation_permitted: false`. It is separate from `tz.payment-operator.v1`, which is a generic
payment-law planning profile and cannot be used as a substitute for VASP authorization.

## Reviewed proposal state

| Axis | Tanzania position in the reviewed comparison | Encoding rule |
|---|---|---|
| Legislative model | Bespoke VA/VASP Act proposed; Bill targeted for September 2026, readings and regulations targeted for November 2026, and an FY 2026/27 effective target | Targets remain non-binding metadata; no activation window |
| Supervisors | BOT for payment/stablecoin functions, CMSA for investment/market functions, and FIU for AML/CFT oversight | Proposed scopes only; final allocations required |
| Licensing scope | Mandatory licensing and express targeting of cross-border providers serving Tanzanian residents are proposed; that targeting intent is broader than Kenya's enacted wording | No operator may be admitted from this proposal pack |
| Categories | Kenya's ten-category structure is a comparison reference; Tanzania's final categories are not specified | Empty `categories`; status `TBD` |
| Capital | No final category-specific minimum capital schedule | Empty amounts; status `TBD` |
| Applicant form and presence | Entity type, local registration, office, bank account, and natural-person eligibility are unresolved | Every field remains `TBD` |
| Legal character | A tradeable/transferable digital representation of value usable for payment or investment is proposed, excluding fiat and regulated e-money | Preserve as proposal metadata; do not infer final definitions |
| Legal tender | A rule that virtual assets are not legal tender is proposed | Encode as `proposed_false`, not enacted fact |
| AML/CFT | FATF Recommendations 15 and 16 and the Travel Rule are contemplated | Proposed obligations only |
| Transition | Length and legal trigger are unspecified | Both remain `TBD` |
| Sandbox | The reviewed snapshot reports a functioning BOT sandbox with three VASPs and no permanent exit path | Sandbox participation is not a licence or production authorization |

The comparison also notes BOT's existing e-money licensing restriction to MNOs and Kenya's
corporate/local-presence model as policy context. Neither is encoded as a Tanzanian VASP rule.
Likewise, the concept note commends comparator prohibitions but does not settle Tanzania's final
prohibited-services list.

## Non-activation gates

The Tanzania VASP proposal profile must remain non-executable until all of the following are
available, reviewed, and represented by a new versioned implementation:

1. Enacted primary legislation and gazetted operative regulations.
2. An authoritative source snapshot commitment and qualified Tanzanian counsel assessment.
3. Final activity categories, BOT/CMSA/FIU allocations, licensing perimeter, capital amounts,
   applicant form, local-presence requirements, prohibited activities, and transition rules.
4. A named operator and independently verified licence or authorization for its exact activities.
5. Canonical activation types, control commitments, bounded validity, deterministic negative
   tests, and independent deployment approval.

The comparison recommends tying any transition clock to gazettement of operative regulations
rather than Act commencement. That is captured only as a non-binding policy recommendation; it is
not represented as current or proposed Tanzanian law.
