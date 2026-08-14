//! The control register: what Kenya activation requires, and what is recorded.
//!
//! This is evidence collection, not a jurisdiction picker. There is no dropdown
//! and nothing here activates anything — a compliance owner uses it to see what
//! is still missing before a profile could exist at all.
//!
//! The distinction matters because of how the profile type behaves.
//! `KenyaRegulatedProfileV1::new` refuses any commitment left at zero, so a
//! constructed profile always has every commitment present. There is no
//! half-complete profile to inspect. The gaps therefore live *before* the
//! profile does, which is exactly the state this register describes.
//!
//! Readiness is computed from the recorded commitments and the mask the
//! activity requires. It is never asserted by a caller, because a register that
//! could be told it was ready would be a claim rather than a finding.

use activechain_protocol_types::KenyaControlSet;

/// The disclaimer the code already carries, surfaced wherever the register is.
///
/// Verbatim from `KenyaControlSet`, because a register that quietly softened it
/// would be the place someone reads a licence into a set of bits.
pub const CONTROL_SET_DISCLAIMER: &str = "These bits commit to accountable off-chain controls. They are not a licence, \
     regulatory approval, reserve balance, or legal conclusion by themselves.";

/// Which regulated activity a register is being assembled for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activity {
    VirtualAssetService,
    StablecoinIssuance,
}

impl Activity {
    /// The mask this activity must satisfy in full.
    #[must_use]
    pub const fn required_mask(self) -> u32 {
        match self {
            Self::VirtualAssetService => KenyaControlSet::VASP_REQUIRED,
            Self::StablecoinIssuance => KenyaControlSet::STABLECOIN_REQUIRED,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::VirtualAssetService => "virtual asset service",
            Self::StablecoinIssuance => "stablecoin issuance",
        }
    }
}

/// One control family, the commitment that backs it, and who answers for it.
///
/// `commitment` names the field on the profile that carries this family's
/// evidence. Several families share one commitment: the law groups obligations
/// more finely than the record does, and pretending otherwise would show a
/// compliance owner eighteen independent gaps where there are fewer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlFamily {
    pub bit: u32,
    pub name: &'static str,
    pub commitment: &'static str,
    pub accountable: &'static str,
}

/// Every family in Kenya Legal Notice No. 134 of 2026, in bit order.
pub const CONTROL_FAMILIES: [ControlFamily; 18] = [
    ControlFamily {
        bit: KenyaControlSet::LICENSING,
        name: "Licensing",
        commitment: "regulatory_authorization",
        accountable: "legal",
    },
    ControlFamily {
        bit: KenyaControlSet::ONGOING_OBLIGATIONS,
        name: "Ongoing obligations",
        commitment: "governance_policy",
        accountable: "compliance",
    },
    ControlFamily {
        bit: KenyaControlSet::CDD_AML_AND_TRANSACTION_INFORMATION,
        name: "CDD, AML and transaction information",
        commitment: "screening_policy",
        accountable: "compliance",
    },
    ControlFamily {
        bit: KenyaControlSet::GOVERNANCE_AND_RISK,
        name: "Governance and risk",
        commitment: "governance_policy",
        accountable: "board",
    },
    ControlFamily {
        bit: KenyaControlSet::CAPITAL_AUDIT_AND_REPORTING,
        name: "Capital, audit and reporting",
        commitment: "reporting_policy",
        accountable: "finance",
    },
    ControlFamily {
        bit: KenyaControlSet::CYBERSECURITY_AND_CONTINUITY,
        name: "Cybersecurity and continuity",
        commitment: "cybersecurity_policy",
        accountable: "engineering",
    },
    ControlFamily {
        bit: KenyaControlSet::ASSET_SAFEKEEPING,
        name: "Asset safekeeping",
        commitment: "custody_policy",
        accountable: "operations",
    },
    ControlFamily {
        bit: KenyaControlSet::CONSUMER_PROTECTION,
        name: "Consumer protection",
        commitment: "consumer_protection_policy",
        accountable: "compliance",
    },
    ControlFamily {
        bit: KenyaControlSet::MARKET_CONDUCT,
        name: "Market conduct",
        commitment: "consumer_protection_policy",
        accountable: "compliance",
    },
    ControlFamily {
        bit: KenyaControlSet::ADVERTISING,
        name: "Advertising",
        commitment: "consumer_protection_policy",
        accountable: "marketing",
    },
    ControlFamily {
        bit: KenyaControlSet::FREEZING_AND_SEIZURE,
        name: "Freezing and seizure",
        commitment: "enforcement_policy",
        accountable: "legal",
    },
    ControlFamily {
        bit: KenyaControlSet::ENFORCEMENT_AND_EXIT,
        name: "Enforcement and exit",
        commitment: "enforcement_policy",
        accountable: "legal",
    },
    ControlFamily {
        bit: KenyaControlSet::RECORDS_AND_REGULATOR_ACCESS,
        name: "Records and regulator access",
        commitment: "privacy_policy",
        accountable: "compliance",
    },
    ControlFamily {
        bit: KenyaControlSet::CONFLICTS_AND_OUTSOURCING,
        name: "Conflicts and outsourcing",
        commitment: "governance_policy",
        accountable: "board",
    },
    ControlFamily {
        bit: KenyaControlSet::STABLECOIN_WHITE_PAPER,
        name: "Stablecoin white paper",
        commitment: "white_paper_approval",
        accountable: "legal",
    },
    ControlFamily {
        bit: KenyaControlSet::STABLECOIN_ISSUANCE_AND_REDEMPTION,
        name: "Stablecoin issuance and redemption",
        commitment: "redemption_policy",
        accountable: "treasury",
    },
    ControlFamily {
        bit: KenyaControlSet::STABLECOIN_RESERVES_AND_CUSTODY,
        name: "Stablecoin reserves and custody",
        commitment: "reserve_policy",
        accountable: "treasury",
    },
    ControlFamily {
        bit: KenyaControlSet::STABLECOIN_AUDIT_REPORTING_AND_HALT,
        name: "Stablecoin audit, reporting and halt",
        commitment: "reporting_policy",
        accountable: "finance",
    },
];

/// One row of the register as a compliance owner reads it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RegisterRow {
    pub name: &'static str,
    pub commitment: &'static str,
    pub accountable: &'static str,
    /// Whether this activity needs the family at all.
    pub required: bool,
    /// Whether the commitment backing it has been recorded.
    pub recorded: bool,
}

/// The register, and what it computes about readiness.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ControlRegister {
    pub activity: &'static str,
    pub rows: Vec<RegisterRow>,
    /// Families this activity requires whose commitment is still missing.
    pub outstanding: Vec<&'static str>,
    /// Computed, never asserted: whether a profile could be constructed at all.
    pub ready: bool,
    pub disclaimer: &'static str,
}

/// Builds the register for an activity from the commitments recorded so far.
///
/// `recorded` names the commitment fields an operator has evidence for. A
/// family counts as recorded only when its backing commitment is present, so a
/// shared commitment satisfies every family that leans on it — which is the
/// truth about the record, and better than showing a gap that filing one
/// document would not close.
///
/// `legal_review` is deliberately not special-cased. It is one commitment among
/// the rest and appears as loudly as any other gap, because the failure this
/// avoids is a register that looks nearly complete while the one document a
/// regulator asks for first is absent.
#[must_use]
pub fn register(activity: Activity, recorded: &[&str]) -> ControlRegister {
    let mask = activity.required_mask();
    let is_recorded = |field: &'static str| recorded.contains(&field);
    let rows: Vec<RegisterRow> = CONTROL_FAMILIES
        .iter()
        .map(|family| RegisterRow {
            name: family.name,
            commitment: family.commitment,
            accountable: family.accountable,
            required: mask & family.bit != 0,
            recorded: is_recorded(family.commitment),
        })
        .collect();
    let outstanding: Vec<&'static str> =
        rows.iter().filter(|row| row.required && !row.recorded).map(|row| row.name).collect();
    // Every profile carries these regardless of activity, so a register that
    // ignored them would call an unconstructable profile ready.
    let common_missing = ["source", "legal_review", "credential_policy", "travel_rule_policy"]
        .into_iter()
        .any(|field| !is_recorded(field));
    let ready = outstanding.is_empty() && !common_missing;
    ControlRegister {
        activity: activity.label(),
        rows,
        outstanding,
        ready,
        disclaimer: CONTROL_SET_DISCLAIMER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every commitment a complete VASP profile needs, by field name.
    fn vasp_evidence() -> Vec<&'static str> {
        vec![
            "source",
            "legal_review",
            "regulatory_authorization",
            "credential_policy",
            "screening_policy",
            "travel_rule_policy",
            "privacy_policy",
            "reporting_policy",
            "governance_policy",
            "consumer_protection_policy",
            "cybersecurity_policy",
            "enforcement_policy",
            "custody_policy",
        ]
    }

    /// The register must describe the law, not a subset someone typed twice.
    #[test]
    fn every_control_family_is_present_exactly_once() {
        assert_eq!(CONTROL_FAMILIES.len(), 18);
        let mut mask = 0_u32;
        for family in CONTROL_FAMILIES {
            assert_eq!(mask & family.bit, 0, "{} duplicates a bit", family.name);
            mask |= family.bit;
        }
        assert_eq!(mask, KenyaControlSet::STABLECOIN_REQUIRED, "every bit is accounted for");
    }

    /// A stablecoin issuer answers for four families a VASP does not.
    #[test]
    fn stablecoin_requires_four_families_a_vasp_does_not() {
        let vasp = register(Activity::VirtualAssetService, &[]);
        let stablecoin = register(Activity::StablecoinIssuance, &[]);
        let required = |r: &ControlRegister| r.rows.iter().filter(|row| row.required).count();
        assert_eq!(required(&vasp), 14);
        assert_eq!(required(&stablecoin), 18);
        assert!(
            stablecoin.outstanding.contains(&"Stablecoin white paper"),
            "the white paper is a stablecoin obligation"
        );
        assert!(!vasp.outstanding.contains(&"Stablecoin white paper"));
    }

    /// Nothing recorded must read as nothing ready, not as an empty register.
    #[test]
    fn an_empty_register_is_not_ready_and_says_what_is_missing() {
        let empty = register(Activity::VirtualAssetService, &[]);
        assert!(!empty.ready);
        assert_eq!(empty.outstanding.len(), 14, "every required family is outstanding");
    }

    /// Readiness is computed from the evidence; it cannot be handed in.
    #[test]
    fn a_complete_vasp_register_is_ready() {
        let complete = register(Activity::VirtualAssetService, &vasp_evidence());
        assert!(complete.ready, "outstanding: {:?}", complete.outstanding);
        assert!(complete.outstanding.is_empty());
    }

    /// The document a regulator asks for first must not be the one the register
    /// is quietest about.
    #[test]
    fn a_missing_legal_review_is_not_ready_however_complete_the_rest_is() {
        let mut evidence = vasp_evidence();
        evidence.retain(|field| *field != "legal_review");
        let register = register(Activity::VirtualAssetService, &evidence);
        assert!(!register.ready, "a profile cannot be built without a legal review");
    }

    /// A VASP-complete register must not read as ready for stablecoin issuance.
    #[test]
    fn vasp_evidence_does_not_make_a_stablecoin_issuer_ready() {
        let register = register(Activity::StablecoinIssuance, &vasp_evidence());
        assert!(!register.ready);
        for family in [
            "Stablecoin white paper",
            "Stablecoin issuance and redemption",
            "Stablecoin reserves and custody",
        ] {
            assert!(register.outstanding.contains(&family), "{family} must be outstanding");
        }
    }

    /// The disclaimer travels with the register rather than living in a
    /// template someone can forget to include.
    #[test]
    fn the_register_carries_its_disclaimer() {
        let register = register(Activity::StablecoinIssuance, &vasp_evidence());
        assert!(register.disclaimer.contains("not a licence"));
        assert!(register.disclaimer.contains("legal conclusion"));
    }
}
