use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_protocol_types::{AssetId, ChainId, CoinCellId, Digest384, PrincipalId};
use alloc::{vec, vec::Vec};
use proptest::prelude::*;

use super::*;

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn inputs(nullifiers: Vec<Digest384>) -> ShieldedTransferPublicInputs {
    ShieldedTransferPublicInputs::new(
        ChainId::new(digest(1)),
        digest(2),
        AssetId::new(digest(3)),
        digest(4),
        nullifiers,
        vec![digest(20), digest(21)],
        7,
        100,
    )
    .unwrap()
}

#[test]
fn canonical_values_round_trip() {
    let note = ShieldedNote::new(
        ChainId::new(digest(1)),
        AssetId::new(digest(2)),
        digest(3),
        42,
        digest(4),
        digest(5),
    )
    .unwrap();
    assert_eq!(decode_envelope::<ShieldedNote>(&encode_envelope(&note).unwrap()), Ok(note));

    let statement = inputs(vec![digest(10), digest(11)]);
    assert_eq!(
        decode_envelope::<ShieldedTransferPublicInputs>(&encode_envelope(&statement).unwrap()),
        Ok(statement)
    );

    let shield = ShieldIntent::new(
        ChainId::new(digest(1)),
        AssetId::new(digest(2)),
        PrincipalId::new(digest(3)),
        vec![CoinCellId::new(digest(10))],
        CoinCellId::new(digest(11)),
        40,
        2,
        vec![digest(20)],
        100,
    )
    .unwrap();
    assert_eq!(decode_envelope::<ShieldIntent>(&encode_envelope(&shield).unwrap()), Ok(shield));

    let unshield = UnshieldIntent::new(
        ChainId::new(digest(1)),
        AssetId::new(digest(2)),
        digest(3),
        PrincipalId::new(digest(4)),
        30,
        2,
        vec![digest(10)],
        vec![digest(20)],
        100,
    )
    .unwrap();
    assert_eq!(
        decode_envelope::<UnshieldIntent>(&encode_envelope(&unshield).unwrap()),
        Ok(unshield)
    );
}

#[test]
fn commitments_are_domain_and_context_bound() {
    let first = ShieldedNote::new(
        ChainId::new(digest(1)),
        AssetId::new(digest(2)),
        digest(3),
        42,
        digest(4),
        digest(5),
    )
    .unwrap();
    let second = ShieldedNote::new(
        ChainId::new(digest(9)),
        AssetId::new(digest(2)),
        digest(3),
        42,
        digest(4),
        digest(5),
    )
    .unwrap();
    assert_ne!(first.commitment().unwrap(), second.commitment().unwrap());
    let opening =
        NullifierOpening::new(ChainId::new(digest(1)), first.commitment().unwrap(), digest(8), 0);
    assert_ne!(opening.nullifier().unwrap(), first.commitment().unwrap());
}

#[test]
fn viewing_capability_is_scoped_and_height_bounded() {
    assert_eq!(
        ViewingCapability::new(
            ChainId::new(digest(1)),
            AssetId::new(digest(2)),
            PrincipalId::new(digest(3)),
            digest(4),
            digest(0),
            5,
            9,
        ),
        Err(PrivacyError::InvalidViewingScope)
    );
    let capability = ViewingCapability::new(
        ChainId::new(digest(1)),
        AssetId::new(digest(2)),
        PrincipalId::new(digest(3)),
        digest(4),
        digest(5),
        5,
        9,
    )
    .unwrap();
    assert!(!capability.is_valid_at(4));
    assert!(capability.is_valid_at(5));
    assert!(capability.is_valid_at(9));
    assert!(!capability.is_valid_at(10));
}

#[test]
fn domain_pseudonyms_separate_domains_and_epochs() {
    let opening = |domain, epoch| {
        DomainPseudonymOpening::new(ChainId::new(digest(1)), digest(domain), digest(9), epoch)
            .unwrap()
            .pseudonym()
            .unwrap()
    };
    assert_ne!(opening(2, 7), opening(3, 7));
    assert_ne!(opening(2, 7), opening(2, 8));
}

fn private_presentation() -> PrivateCredentialPresentation {
    PrivateCredentialPresentation::new(
        ChainId::new(digest(1)),
        digest(2),
        digest(3),
        PrincipalId::new(digest(4)),
        digest(5),
        digest(6),
        digest(7),
        9,
        100,
        10,
        digest(8),
        digest(9),
        120,
    )
    .unwrap()
}

#[test]
fn private_credential_statement_binds_fresh_finalized_status() {
    let presentation = private_presentation();
    assert_eq!(
        decode_envelope::<PrivateCredentialPresentation>(&encode_envelope(&presentation).unwrap()),
        Ok(presentation)
    );
    let proof = VerifiedPrivacyProof {
        public_inputs_commitment: presentation.commitment().unwrap(),
        verified: true,
    };
    assert_eq!(
        presentation.verify(proof, ChainId::new(digest(1)), digest(2), digest(7), 9, 110),
        Ok(())
    );
    assert_eq!(
        presentation.verify(proof, ChainId::new(digest(1)), digest(2), digest(7), 9, 111),
        Err(PrivacyError::Expired)
    );
    assert_eq!(
        presentation.verify(proof, ChainId::new(digest(1)), digest(2), digest(70), 9, 105),
        Err(PrivacyError::PublicInputMismatch)
    );
}

#[test]
fn credential_proof_substitution_fails_closed() {
    let presentation = private_presentation();
    let wrong = VerifiedPrivacyProof { public_inputs_commitment: digest(99), verified: true };
    assert_eq!(
        presentation.verify(wrong, ChainId::new(digest(1)), digest(2), digest(7), 9, 105),
        Err(PrivacyError::PublicInputMismatch)
    );
}

#[test]
fn disclosure_capabilities_only_attenuate() {
    let capability = |fields, not_before, expires_at| {
        DisclosureCapability::new(
            ChainId::new(digest(1)),
            digest(2),
            PrincipalId::new(digest(3)),
            digest(4),
            digest(5),
            fields,
            not_before,
            expires_at,
        )
        .unwrap()
    };
    let parent = capability(vec![1, 2, 4], 10, 30);
    let child = capability(vec![1, 4], 12, 20);
    assert_eq!(parent.verify_attenuation(&child), Ok(()));
    assert_eq!(
        parent.verify_attenuation(&capability(vec![1, 3], 12, 20)),
        Err(PrivacyError::ScopeEscalation)
    );
    assert_eq!(
        decode_envelope::<DisclosureCapability>(&encode_envelope(&parent).unwrap()),
        Ok(parent)
    );
}

fn private_object_transition() -> PrivateObjectTransition {
    PrivateObjectTransition::new(
        ChainId::new(digest(1)),
        digest(2),
        digest(3),
        digest(4),
        digest(5),
        digest(6),
        digest(7),
        digest(8),
        digest(9),
        digest(10),
        digest(11),
        100,
    )
    .unwrap()
}

#[test]
fn private_object_transition_binds_complete_context() {
    let transition = private_object_transition();
    assert_eq!(
        decode_envelope::<PrivateObjectTransition>(&encode_envelope(&transition).unwrap()),
        Ok(transition)
    );
    let proof = VerifiedPrivacyProof {
        public_inputs_commitment: transition.commitment().unwrap(),
        verified: true,
    };
    assert_eq!(transition.verify(proof, ChainId::new(digest(1)), digest(2), 99), Ok(digest(3)));
    assert_eq!(
        transition.verify(proof, ChainId::new(digest(1)), digest(20), 99),
        Err(PrivacyError::WrongAnchor)
    );
    assert_eq!(
        transition.verify(proof, ChainId::new(digest(1)), digest(2), 101),
        Err(PrivacyError::Expired)
    );
}

#[test]
fn admission_is_fail_closed_and_atomic() {
    let statement = inputs(vec![digest(10), digest(11)]);
    let proof = VerifiedPrivacyProof {
        public_inputs_commitment: statement.commitment().unwrap(),
        verified: true,
    };
    let mut state = NullifierSet::default();
    assert_eq!(
        state.admit(&statement, proof, ChainId::new(digest(1)), digest(99), 10),
        Err(PrivacyError::WrongAnchor)
    );
    assert!(state.as_slice().is_empty());
    state.admit(&statement, proof, ChainId::new(digest(1)), digest(2), 10).unwrap();
    let snapshot = state.clone();
    assert_eq!(
        state.admit(&statement, proof, ChainId::new(digest(1)), digest(2), 10),
        Err(PrivacyError::NullifierAlreadySpent)
    );
    assert_eq!(state, snapshot);
}

#[test]
fn malformed_and_unbound_inputs_are_rejected() {
    assert_eq!(
        ShieldedTransferPublicInputs::new(
            ChainId::new(digest(1)),
            digest(2),
            AssetId::new(digest(3)),
            digest(4),
            vec![digest(10), digest(10)],
            vec![digest(20)],
            0,
            10,
        ),
        Err(PrivacyError::NonCanonicalOrder)
    );
    assert_eq!(
        ShieldedTransferPublicInputs::new(
            ChainId::new(digest(1)),
            digest(2),
            AssetId::new(digest(3)),
            digest(4),
            vec![digest(11), digest(10)],
            vec![digest(20)],
            0,
            10,
        ),
        Err(PrivacyError::NonCanonicalOrder)
    );
    let statement = inputs(vec![digest(10)]);
    let mut state = NullifierSet::default();
    let rejected = VerifiedPrivacyProof { public_inputs_commitment: digest(99), verified: true };
    assert_eq!(
        state.admit(&statement, rejected, ChainId::new(digest(1)), digest(2), 10),
        Err(PrivacyError::PublicInputMismatch)
    );
    assert!(state.as_slice().is_empty());
}

#[test]
fn shielded_cash_state_round_trips_with_persistent_nullifiers() {
    let nullifiers = NullifierSet::new(vec![digest(10), digest(11)]).unwrap();
    let state = ShieldedCashState::new(500, digest(12), nullifiers).unwrap();
    let encoded = encode_envelope(&state).unwrap();
    assert_eq!(decode_envelope::<ShieldedCashState>(&encoded), Ok(state));
}

#[test]
fn verified_nullifier_consumption_is_atomic() {
    let mut set = NullifierSet::new(vec![digest(10)]).unwrap();
    let snapshot = set.clone();
    assert_eq!(
        set.consume_verified(&[digest(9), digest(10)]),
        Err(PrivacyError::NullifierAlreadySpent)
    );
    assert_eq!(set, snapshot);
}

proptest! {
    #[test]
    fn note_commitment_changes_with_value(first in 1_u128..u128::MAX, second in 1_u128..u128::MAX) {
        prop_assume!(first != second);
        let make = |value| ShieldedNote::new(
            ChainId::new(digest(1)), AssetId::new(digest(2)), digest(3), value, digest(4), digest(5),
        ).unwrap();
        prop_assert_ne!(make(first).commitment().unwrap(), make(second).commitment().unwrap());
    }

    #[test]
    fn every_rejected_replay_preserves_state(bytes in prop::collection::btree_set(1_u8..200, 1..16)) {
        let nullifiers = bytes.into_iter().map(digest).collect::<Vec<_>>();
        let statement = inputs(nullifiers);
        let proof = VerifiedPrivacyProof {
            public_inputs_commitment: statement.commitment().unwrap(), verified: true,
        };
        let mut state = NullifierSet::default();
        state.admit(&statement, proof, ChainId::new(digest(1)), digest(2), 1).unwrap();
        let snapshot = state.clone();
        prop_assert_eq!(
            state.admit(&statement, proof, ChainId::new(digest(1)), digest(2), 1),
            Err(PrivacyError::NullifierAlreadySpent)
        );
        prop_assert_eq!(state, snapshot);
    }
}
