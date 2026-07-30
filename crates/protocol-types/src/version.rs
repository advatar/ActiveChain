use crate::{is_reserved_future_type_tag, is_v1_type_tag};

pub const V1_0_PROTOCOL_REVISION: u64 = 1;
pub const V1_1_PROTOCOL_REVISION: u64 = 2;
pub const V1_2_PROTOCOL_REVISION: u64 = 3;
pub const V1_3_PROTOCOL_REVISION: u64 = 4;
pub const V1_4_PROTOCOL_REVISION: u64 = 5;
pub const V2_PROTOCOL_REVISION: u64 = 6;

/// Explicit activation-marker identities reserved by P-131. These do not reinterpret the
/// already-registered development types; they identify the future activation envelopes.
pub const V1_1_EXECUTION_PROOF_ACTIVATION_TAG: u16 = 0x00E0;
pub const V1_2_PRIVATE_CREDENTIAL_ACTIVATION_TAG: u16 = 0x00F0;
pub const V1_2_SHIELDED_PAYMENT_ACTIVATION_TAG: u16 = 0x00F1;
pub const V1_2_PRIVATE_OBJECT_ACTIVATION_TAG: u16 = 0x00F2;
pub const V1_2_VIEWING_CAPABILITY_ACTIVATION_TAG: u16 = 0x00F3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolFeature {
    ExecutionValidityProofs,
    PrivateCredentials,
    ShieldedPayments,
    PrivateObjects,
    ViewingCapabilities,
    ProtectedOrdering,
    ComputeJobs,
    StatelessValidators,
    ExternalBridges,
}

impl ProtocolFeature {
    pub const fn activation_revision(self) -> u64 {
        match self {
            Self::ExecutionValidityProofs => V1_1_PROTOCOL_REVISION,
            Self::PrivateCredentials
            | Self::ShieldedPayments
            | Self::PrivateObjects
            | Self::ViewingCapabilities => V1_2_PROTOCOL_REVISION,
            Self::ProtectedOrdering => V1_3_PROTOCOL_REVISION,
            Self::ComputeJobs => V1_4_PROTOCOL_REVISION,
            Self::StatelessValidators | Self::ExternalBridges => V2_PROTOCOL_REVISION,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderSlotRule {
    /// The slot is encoded and may carry non-authoritative evidence.
    Advisory,
    /// Consensus admission requires the slot and its evidence to verify.
    Required,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolVersionError {
    UnknownRevision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypeDispatchError {
    UnknownRevision,
    UnknownTypeTag,
    UnassignedReservedTag,
    FeatureNotActive,
}

/// Bounded dispatcher for the complete P-131 version series.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolVersionProfile {
    revision: u64,
}

impl ProtocolVersionProfile {
    pub const fn new(revision: u64) -> Result<Self, ProtocolVersionError> {
        if revision < V1_0_PROTOCOL_REVISION || revision > V2_PROTOCOL_REVISION {
            return Err(ProtocolVersionError::UnknownRevision);
        }
        Ok(Self { revision })
    }

    pub const fn revision(self) -> u64 {
        self.revision
    }

    pub const fn requires(self, feature: ProtocolFeature) -> bool {
        self.revision >= feature.activation_revision()
    }

    pub const fn execution_proof_header_slot(self) -> HeaderSlotRule {
        if self.requires(ProtocolFeature::ExecutionValidityProofs) {
            HeaderSlotRule::Required
        } else {
            HeaderSlotRule::Advisory
        }
    }

    /// Applies version gating after the canonical registry has established whether the tag is
    /// assigned. Unknown and unassigned reserved identities never become wildcards.
    pub const fn dispatch_registered_type_tag(
        self,
        tag: u16,
        registered: bool,
    ) -> Result<(), TypeDispatchError> {
        if !registered {
            return Err(TypeDispatchError::UnknownTypeTag);
        }
        if is_reserved_future_type_tag(tag) {
            let Some(feature) = activation_marker_feature(tag) else {
                return Err(TypeDispatchError::UnassignedReservedTag);
            };
            return if self.requires(feature) {
                Ok(())
            } else {
                Err(TypeDispatchError::FeatureNotActive)
            };
        }
        if !is_v1_type_tag(tag) {
            return Err(TypeDispatchError::UnknownTypeTag);
        }
        if let Some(feature) = deferred_registered_type_feature(tag)
            && !self.requires(feature)
        {
            return Err(TypeDispatchError::FeatureNotActive);
        }
        Ok(())
    }
}

const fn activation_marker_feature(tag: u16) -> Option<ProtocolFeature> {
    match tag {
        V1_1_EXECUTION_PROOF_ACTIVATION_TAG => Some(ProtocolFeature::ExecutionValidityProofs),
        V1_2_PRIVATE_CREDENTIAL_ACTIVATION_TAG => Some(ProtocolFeature::PrivateCredentials),
        V1_2_SHIELDED_PAYMENT_ACTIVATION_TAG => Some(ProtocolFeature::ShieldedPayments),
        V1_2_PRIVATE_OBJECT_ACTIVATION_TAG => Some(ProtocolFeature::PrivateObjects),
        V1_2_VIEWING_CAPABILITY_ACTIVATION_TAG => Some(ProtocolFeature::ViewingCapabilities),
        _ => None,
    }
}

/// Existing development types retain their unique v1 identities but cannot enter consensus before
/// the version named by P-131. The ranges mirror the canonical registry and are deliberately
/// explicit rather than treating a broad tag block as activated.
const fn deferred_registered_type_feature(tag: u16) -> Option<ProtocolFeature> {
    match tag {
        0x00A0 | 0x00A1 | 0x00A3..=0x00A7 => Some(ProtocolFeature::ShieldedPayments),
        0x00A2 | 0x00AA => Some(ProtocolFeature::ViewingCapabilities),
        0x00A8 | 0x00A9 => Some(ProtocolFeature::PrivateCredentials),
        0x00AB => Some(ProtocolFeature::PrivateObjects),
        0x00AC..=0x00B9 => Some(ProtocolFeature::ProtectedOrdering),
        0x00C3..=0x00C5 => Some(ProtocolFeature::ComputeJobs),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_revisions_fail_closed() {
        assert_eq!(ProtocolVersionProfile::new(0), Err(ProtocolVersionError::UnknownRevision));
        assert_eq!(ProtocolVersionProfile::new(7), Err(ProtocolVersionError::UnknownRevision));
        for revision in V1_0_PROTOCOL_REVISION..=V2_PROTOCOL_REVISION {
            assert_eq!(ProtocolVersionProfile::new(revision).unwrap().revision(), revision);
        }
    }

    #[test]
    fn features_activate_only_at_their_named_revision() {
        let features = [
            ProtocolFeature::ExecutionValidityProofs,
            ProtocolFeature::PrivateCredentials,
            ProtocolFeature::ShieldedPayments,
            ProtocolFeature::PrivateObjects,
            ProtocolFeature::ViewingCapabilities,
            ProtocolFeature::ProtectedOrdering,
            ProtocolFeature::ComputeJobs,
            ProtocolFeature::StatelessValidators,
            ProtocolFeature::ExternalBridges,
        ];
        for feature in features {
            for revision in V1_0_PROTOCOL_REVISION..=V2_PROTOCOL_REVISION {
                let profile = ProtocolVersionProfile::new(revision).unwrap();
                assert_eq!(profile.requires(feature), revision >= feature.activation_revision());
            }
        }
    }

    #[test]
    fn reserved_and_deferred_tags_never_act_as_wildcards() {
        let v10 = ProtocolVersionProfile::new(V1_0_PROTOCOL_REVISION).unwrap();
        let v11 = ProtocolVersionProfile::new(V1_1_PROTOCOL_REVISION).unwrap();
        let v12 = ProtocolVersionProfile::new(V1_2_PROTOCOL_REVISION).unwrap();
        assert_eq!(
            v10.dispatch_registered_type_tag(V1_1_EXECUTION_PROOF_ACTIVATION_TAG, true),
            Err(TypeDispatchError::FeatureNotActive)
        );
        assert_eq!(
            v11.dispatch_registered_type_tag(V1_1_EXECUTION_PROOF_ACTIVATION_TAG, true),
            Ok(())
        );
        assert_eq!(
            v12.dispatch_registered_type_tag(V1_1_EXECUTION_PROOF_ACTIVATION_TAG + 1, true),
            Err(TypeDispatchError::UnassignedReservedTag)
        );
        assert_eq!(
            v12.dispatch_registered_type_tag(0x0100, false),
            Err(TypeDispatchError::UnknownTypeTag)
        );
    }

    #[test]
    fn frozen_launch_vector_matches_the_dispatcher() {
        let expected = "case\trevision\ttag\tregistered\texpected\treason\n\
core_v10\t1\t0x0020\ttrue\taccept\tknown core type remains active\n\
v11_marker_before_activation\t1\t0x00E0\ttrue\treject-feature\tv1.0 cannot require proof validity\n\
v11_marker_at_activation\t2\t0x00E0\ttrue\taccept\tv1.1 activates proof validity\n\
unassigned_reserved_after_activation\t3\t0x00E1\ttrue\treject-reserved\treserved ranges are not wildcards\n\
shielded_before_activation\t2\t0x00A0\ttrue\treject-feature\tv1.1 cannot admit shielded payments\n\
shielded_at_activation\t3\t0x00A0\ttrue\taccept\tv1.2 activates shielded payments\n\
protected_before_activation\t3\t0x00AD\ttrue\treject-feature\tv1.2 cannot require protected ordering\n\
protected_at_activation\t4\t0x00AD\ttrue\taccept\tv1.3 activates protected ordering\n\
compute_before_activation\t4\t0x00C5\ttrue\treject-feature\tv1.3 cannot admit compute jobs\n\
compute_at_activation\t5\t0x00C5\ttrue\taccept\tv1.4 activates compute jobs\n\
unknown_extended\t6\t0x0100\tfalse\treject-unknown\tunknown registered status fails closed\n\
header_v10\t1\tproof-slot\ttrue\tadvisory\tv1.0 slot cannot replace re-execution\n\
header_v11\t2\tproof-slot\ttrue\trequired\tv1.1 requires proof validity\n";
        assert_eq!(include_str!("../../../testing/vectors/launch-sequencing-v1.tsv"), expected);

        for line in expected.lines().skip(1) {
            let fields: alloc::vec::Vec<_> = line.split('\t').collect();
            let revision = fields[1].parse::<u64>().unwrap();
            let profile = ProtocolVersionProfile::new(revision).unwrap();
            if fields[2] == "proof-slot" {
                let expected_rule = if fields[4] == "advisory" {
                    HeaderSlotRule::Advisory
                } else {
                    HeaderSlotRule::Required
                };
                assert_eq!(profile.execution_proof_header_slot(), expected_rule);
                continue;
            }
            let tag = u16::from_str_radix(fields[2].trim_start_matches("0x"), 16).unwrap();
            let registered = fields[3].parse::<bool>().unwrap();
            let result = profile.dispatch_registered_type_tag(tag, registered);
            match fields[4] {
                "accept" => assert_eq!(result, Ok(())),
                "reject-feature" => assert_eq!(result, Err(TypeDispatchError::FeatureNotActive)),
                "reject-reserved" => {
                    assert_eq!(result, Err(TypeDispatchError::UnassignedReservedTag));
                }
                "reject-unknown" => assert_eq!(result, Err(TypeDispatchError::UnknownTypeTag)),
                _ => panic!("unknown vector result"),
            }
        }
    }
}
