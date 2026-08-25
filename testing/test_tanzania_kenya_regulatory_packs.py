import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPLIANCE = ROOT / "docs" / "compliance"
EXPECTED_COMPARISON_SHA256 = (
    "cd4da651c0e3d367f2b200cab864d57add595e2bb59aa676b9e7063483cb3f30"
)


def load_json(relative_path: str) -> dict:
    return json.loads((COMPLIANCE / relative_path).read_text(encoding="utf-8"))


class TanzaniaKenyaRegulatoryPackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.kenya = load_json("packs/ke.vasp-regime.2026.json")
        cls.tanzania = load_json("packs/tz.vasp-proposal.2026.json")

    def test_comparison_snapshot_is_pinned_for_both_packs(self) -> None:
        for pack in (self.kenya, self.tanzania):
            self.assertEqual(
                pack["comparison_source"]["sha256"], EXPECTED_COMPARISON_SHA256
            )
            self.assertEqual(pack["comparison_source"]["prepared_date"], "2026-08-20")
            self.assertEqual(
                pack["comparison_source"]["role"],
                "internal_comparison_snapshot_not_authoritative_law",
            )

    def test_kenya_activity_capital_and_supervisor_matrix(self) -> None:
        expected = {
            "wallet_provision": ("CBK", 150_000_000),
            "exchange_operation": ("CMA", 100_000_000),
            "payment_processing": ("CBK", 10_000_000),
            "brokerage": ("CMA", 10_000_000),
            "investment_advisory": ("CMA", 0),
            "asset_management": ("CMA", 20_000_000),
            "ico_issuance": ("CMA", 20_000_000),
            "real_world_asset_tokenisation": ("CMA", 10_000_000),
            "token_issuance_platform": ("CMA", 20_000_000),
            "stablecoin_issuance": ("CBK", 300_000_000),
        }
        actual = {
            item["id"]: (item["supervisor"], item["minimum_capital_kes"])
            for item in self.kenya["activity_categories"]
        }
        self.assertEqual(actual, expected)

        by_authority = {
            supervisor["code"]: set(supervisor["activities"])
            for supervisor in self.kenya["supervisors"]
        }
        for activity, (authority, _) in expected.items():
            self.assertIn(activity, by_authority[authority])

    def test_kenya_entity_scope_and_transition_are_explicit(self) -> None:
        self.assertEqual(self.kenya["status"], "enacted_activation_gated")
        self.assertTrue(self.kenya["activation_permitted"])
        applicants = self.kenya["applicant_requirements"]
        self.assertEqual(applicants["entity_type"], "company_limited_by_shares")
        self.assertTrue(applicants["foreign_company_must_be_registered_in_kenya"])
        self.assertTrue(applicants["physical_office_in_kenya"])
        self.assertTrue(applicants["local_bank_account"])
        self.assertEqual(applicants["natural_person_applicant"], "prohibited")
        self.assertEqual(
            applicants["exact_board_size"], "not_encoded_source_unconfirmed"
        )
        self.assertEqual(self.kenya["scope"]["act_application_clause"], "services_in_kenya")
        self.assertEqual(
            self.kenya["scope"]["licensing_prohibition"],
            "unlicensed_services_in_or_from_kenya",
        )
        self.assertFalse(
            self.kenya["scope"]["express_nonresident_provider_targeting_test"]
        )
        self.assertFalse(self.kenya["scope"]["virtual_assets_are_legal_tender"])
        self.assertEqual(
            self.kenya["transition"]["existing_provider_deadline"], "2026-11-04"
        )
        self.assertEqual(self.kenya["transition"]["period_months"], 12)
        self.assertEqual(self.kenya["transition"]["published_bill_period_months"], 6)

        provenance = self.kenya["consultation_provenance"]
        self.assertEqual(provenance["stablecoin_capital_draft_kes"], 500_000_000)
        self.assertEqual(provenance["stablecoin_capital_final_kes"], 300_000_000)
        self.assertEqual(provenance["investment_adviser_capital_draft_kes"], 2_500_000)
        self.assertEqual(provenance["investment_adviser_capital_final_kes"], 0)
        self.assertEqual(provenance["final_single_shareholder_cap"], "dropped")

    def test_tanzania_is_proposal_only_and_unresolved_fields_stay_unresolved(self) -> None:
        self.assertEqual(self.tanzania["status"], "proposal_only")
        self.assertFalse(self.tanzania["activation_permitted"])
        self.assertFalse(self.tanzania["legal_framework"]["targets_are_binding"])
        self.assertEqual(
            self.tanzania["activity_categories"]["status"],
            "TBD_TO_BE_SET_IN_REGULATIONS",
        )
        self.assertEqual(self.tanzania["activity_categories"]["categories"], [])
        self.assertEqual(self.tanzania["capital_requirements"]["status"], "TBD")
        self.assertEqual(self.tanzania["capital_requirements"]["amounts"], [])
        self.assertTrue(
            all(
                value == "TBD"
                for value in self.tanzania["applicant_requirements"].values()
            )
        )
        self.assertEqual(self.tanzania["transition"]["length"], "TBD")
        self.assertEqual(self.tanzania["transition"]["trigger"], "TBD")
        self.assertEqual(self.tanzania["sandbox"]["vasp_participants"], 3)
        self.assertEqual(
            self.tanzania["scope"]["cross_border_resident_targeting"],
            "expressly_proposed",
        )
        self.assertEqual(
            self.tanzania["scope"]["virtual_assets_are_legal_tender"],
            "proposed_false",
        )

    def test_profiles_reference_existing_packs_and_preserve_activation_boundaries(self) -> None:
        profile_names = (
            "ke.virtual-asset-service.v2.json",
            "ke.stablecoin-issuer.v1.json",
            "tz.virtual-asset-service-proposal.v1.json",
        )
        for profile_name in profile_names:
            profile_path = COMPLIANCE / "profiles" / profile_name
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertTrue((profile_path.parent / profile["regulatory_pack"]).resolve().is_file())

        kenya_vasp = load_json("profiles/ke.virtual-asset-service.v2.json")
        kenya_stablecoin = load_json("profiles/ke.stablecoin-issuer.v1.json")
        self.assertEqual(kenya_vasp["status"], "activation_gated")
        self.assertEqual(kenya_stablecoin["status"], "activation_gated")

        tanzania_vasp = load_json("profiles/tz.virtual-asset-service-proposal.v1.json")
        self.assertEqual(tanzania_vasp["status"], "proposal_only")
        self.assertFalse(tanzania_vasp["activation_permitted"])
        self.assertEqual(tanzania_vasp["protocol_type"], "NOT_IMPLEMENTED")
        self.assertEqual(tanzania_vasp["effective_height"], 0)
        self.assertEqual(tanzania_vasp["expires_height"], 0)

        payment = load_json("profiles/tz.payment-operator.v1.json")
        self.assertEqual(payment["activity"], "payment_operator")
        self.assertIn("not VASP authorization", payment["vasp_boundary"])


if __name__ == "__main__":
    unittest.main()
