extern crate alloc;

use alloc::vec;

use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_policy_kernel::{
    APL_LANGUAGE_VERSION, ActorBinding, PolicyRequest, PolicyRequestFields, PolicySet,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    AccessManifest, AccessManifestFields, ChainId, Digest384, FreezeState, ObjectId, ObjectOwner,
    ObjectVersionRef, PrincipalId,
};
use activechain_transition::{TRANSFER_OBJECT_ACTION_ID, TransferCommand, TransferTransaction};
use proptest::prelude::*;

use crate::{
    ACTION_PROTOCOL_VERSION, ActionEnvelope, ActionEnvelopeError, FeeTicket, FeeTicketError,
    NonceAdvanceError, NonceChannel, ResourcePrices, ResourceVector, ValidityInterval,
    ValidityIntervalError, action_id,
};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn sender() -> PrincipalId {
    PrincipalId::new(digest(0x11))
}

fn transfer(actor: PrincipalId, height: u64) -> TransferTransaction {
    let object_id = ObjectId::new(digest(0x20));
    let input = ObjectVersionRef::new(object_id, 7);
    let manifest = AccessManifest::new(AccessManifestFields {
        exact_reads: vec![],
        exact_writes: vec![input],
        immutable_reads: vec![],
        creation_namespaces: vec![],
        maximum_created_objects: 0,
        maximum_dynamic_reads: 0,
        dynamic_read_policy: None,
    })
    .expect("test manifest is canonical");
    let policy = PolicySet::new(APL_LANGUAGE_VERSION, vec![]).expect("empty policy is bounded");
    let request = PolicyRequest::new(PolicyRequestFields {
        actor: ActorBinding::Principal(actor),
        action: TRANSFER_OBJECT_ACTION_ID,
        resource: object_id,
        height,
        value: 0,
        freeze_state: FreezeState::Active,
        declared_purpose: None,
        credential_schemas: vec![],
        capabilities: vec![],
        approvals: vec![],
    })
    .expect("test request is canonical");
    TransferTransaction::new(
        height,
        manifest,
        vec![TransferCommand::new(input, ObjectOwner::Shared, policy, request)],
    )
    .expect("test transaction is canonical")
}

fn resources() -> ResourceVector {
    ResourceVector::new(100, 0, 1, 0, 0, 2_000)
}

fn ticket(permitted_resources: ResourceVector) -> FeeTicket {
    FeeTicket::new(
        ObjectId::new(digest(0x30)),
        PrincipalId::new(digest(0x31)),
        100_000,
        100,
        9,
        permitted_resources,
    )
    .expect("test fee ticket is valid")
}

fn envelope_for(actor: PrincipalId, payload: TransferTransaction) -> ActionEnvelope {
    let payload_commitment =
        commit(DomainTag::CANONICAL_VALUE, &payload).expect("test payload commits");
    ActionEnvelope::new(
        ACTION_PROTOCOL_VERSION,
        ChainId::new(digest(0x40)),
        actor,
        ticket(resources()),
        2,
        5,
        ValidityInterval::new(40, 60).expect("test validity is ordered"),
        resources(),
        payload_commitment,
        payload,
        digest(0x50),
    )
    .expect("test envelope is valid")
}

#[test]
fn resource_dimensions_compare_and_charge_independently() {
    let usage = ResourceVector::new(2, 3, 5, 7, 11, 13);
    let ceiling = ResourceVector::new(2, 3, 5, 7, 11, 13);
    assert!(usage.fits_within(ceiling));
    assert!(!ResourceVector::new(3, 0, 0, 0, 0, 0).fits_within(ceiling));
    assert_eq!(usage.checked_charge(ResourcePrices::new(1, 2, 3, 4, 5, 6)), Some(184));
    assert_eq!(
        ResourceVector::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX)
            .checked_charge(ResourcePrices::new(
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            )),
        None
    );
}

#[test]
fn validity_and_fee_ticket_constructors_reject_invalid_shapes() {
    assert_eq!(ValidityInterval::new(8, 7), Err(ValidityIntervalError::Inverted));
    assert_eq!(
        FeeTicket::new(ObjectId::new(digest(1)), sender(), 0, 10, 0, ResourceVector::default(),),
        Err(FeeTicketError::ZeroReservation)
    );
}

#[test]
fn action_envelope_round_trips_and_identifier_binds_authorization_evidence() {
    let envelope = envelope_for(sender(), transfer(sender(), 50));
    let encoded = encode_envelope(&envelope).expect("action envelope encodes");
    assert_eq!(decode_envelope(&encoded), Ok(envelope.clone()));
    assert_eq!(action_id(&envelope), action_id(&envelope));

    let changed = ActionEnvelope::new(
        envelope.protocol_version(),
        envelope.chain_id(),
        envelope.sender(),
        envelope.fee_ticket(),
        envelope.nonce_channel(),
        envelope.sequence(),
        envelope.validity(),
        envelope.maximum_resources(),
        envelope.payload_commitment(),
        envelope.payload().clone(),
        digest(0x51),
    )
    .expect("changed evidence remains structural");
    assert_ne!(action_id(&envelope), action_id(&changed));
}

#[test]
fn envelope_rejects_payload_actor_commitment_height_and_ticket_mismatches() {
    let payload = transfer(sender(), 50);
    let expected = commit(DomainTag::CANONICAL_VALUE, &payload).expect("payload commits");
    let validity = ValidityInterval::new(40, 60).expect("ordered");
    let base_ticket = ticket(resources());

    assert_eq!(
        ActionEnvelope::new(
            2,
            ChainId::new(digest(0x40)),
            sender(),
            base_ticket,
            2,
            5,
            validity,
            resources(),
            expected,
            payload.clone(),
            digest(0x50),
        ),
        Err(ActionEnvelopeError::UnsupportedProtocolVersion(2))
    );
    assert_eq!(
        ActionEnvelope::new(
            1,
            ChainId::new(digest(0x40)),
            sender(),
            base_ticket,
            2,
            5,
            validity,
            resources(),
            digest(0xff),
            payload.clone(),
            digest(0x50),
        ),
        Err(ActionEnvelopeError::PayloadCommitmentMismatch)
    );
    assert_eq!(
        ActionEnvelope::new(
            1,
            ChainId::new(digest(0x40)),
            sender(),
            base_ticket,
            2,
            5,
            ValidityInterval::new(51, 60).expect("ordered"),
            resources(),
            expected,
            payload.clone(),
            digest(0x50),
        ),
        Err(ActionEnvelopeError::PayloadHeightOutsideValidity)
    );
    let other = PrincipalId::new(digest(0x12));
    assert!(matches!(
        ActionEnvelope::new(
            1,
            ChainId::new(digest(0x40)),
            other,
            base_ticket,
            2,
            5,
            validity,
            resources(),
            expected,
            payload.clone(),
            digest(0x50),
        ),
        Err(ActionEnvelopeError::SenderActorMismatch)
    ));
    let too_small = ticket(ResourceVector::new(99, 0, 1, 0, 0, 2_000));
    assert!(matches!(
        ActionEnvelope::new(
            1,
            ChainId::new(digest(0x40)),
            sender(),
            too_small,
            2,
            5,
            validity,
            resources(),
            expected,
            payload,
            digest(0x50),
        ),
        Err(ActionEnvelopeError::ResourcesExceedTicket)
    ));
}

#[test]
fn nonce_channel_distinguishes_replay_gap_and_exhaustion() {
    let channel = NonceChannel::new(sender(), 2, 5);
    assert_eq!(channel.advance(5).map(NonceChannel::next_sequence), Ok(6));
    assert_eq!(channel.advance(4), Err(NonceAdvanceError::Replay { supplied: 4, expected: 5 }));
    assert_eq!(
        channel.advance(6),
        Err(NonceAdvanceError::SequenceGap { supplied: 6, expected: 5 })
    );
    assert_eq!(
        NonceChannel::new(sender(), 2, u64::MAX).advance(u64::MAX),
        Err(NonceAdvanceError::SequenceExhausted)
    );
}

#[test]
fn fixed_fee_and_nonce_types_have_published_lengths() {
    assert_eq!(
        encode_envelope(&ticket(resources())).expect("ticket encodes").len(),
        2 + 2 + 2 + FeeTicket::ENCODED_LENGTH
    );
    let channel = NonceChannel::new(sender(), 2, 5);
    assert_eq!(
        encode_envelope(&channel).expect("channel encodes").len(),
        2 + 2 + 1 + NonceChannel::ENCODED_LENGTH
    );
}

proptest! {
    #[test]
    fn every_non_exhausted_exact_nonce_advances_once(next in 0_u64..u64::MAX) {
        let channel = NonceChannel::new(sender(), 9, next);
        let advanced = channel.advance(next).expect("non-exhausted exact nonce advances");
        prop_assert_eq!(advanced.next_sequence(), next + 1);
        let replayed = matches!(
            advanced.advance(next),
            Err(NonceAdvanceError::Replay { .. })
        );
        prop_assert!(replayed);
    }
}
