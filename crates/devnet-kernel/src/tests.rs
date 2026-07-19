extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use activechain_action_kernel::{
    ACTION_PROTOCOL_VERSION, ActionEnvelope, FeeTicket, NonceAdvanceError, NonceChannel,
    ResourcePrices, ResourceVector, ValidityInterval, action_id,
};
use activechain_canonical_codec::{decode_envelope, encode_body, encode_envelope};
use activechain_policy_kernel::{
    APL_LANGUAGE_VERSION, ActorBinding, PolicyEffect, PolicyPredicate, PolicyRequest,
    PolicyRequestFields, PolicyRule, PolicySet,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    AccessManifest, AccessManifestFields, ChainId, Digest384, FreezeState, Object, ObjectFields,
    ObjectFlags, ObjectId, ObjectOwner, ObjectVersionRef, PrincipalId, ResourceSelector,
    TransactionId,
};
use activechain_state_tree::{StateCommitment, commit_objects};
use activechain_transition::{
    ObjectState, ReceiptResult, TRANSFER_OBJECT_ACTION_ID, TransferCommand, TransferTransaction,
    TransitionReceipt,
};

use crate::{
    ActionOutcome, ActionReceipt, BlockApplyError, BlockReceipt, ChainState, DevnetBlock,
    apply_block,
};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn chain_id() -> ChainId {
    ChainId::new(digest(0x01))
}

fn sender() -> PrincipalId {
    PrincipalId::new(digest(0x02))
}

fn object_id() -> ObjectId {
    ObjectId::new(digest(0x10))
}

fn policy() -> PolicySet {
    PolicySet::new(
        APL_LANGUAGE_VERSION,
        vec![
            PolicyRule::new(
                PolicyEffect::Permit,
                vec![
                    PolicyPredicate::ActorIs(ActorBinding::Principal(sender())),
                    PolicyPredicate::ActionIs(TRANSFER_OBJECT_ACTION_ID),
                    PolicyPredicate::ResourceMatches(ResourceSelector::exact(object_id())),
                    PolicyPredicate::FreezeStateIs(FreezeState::Active),
                ],
                vec![],
            )
            .expect("devnet test policy rule is valid"),
        ],
    )
    .expect("devnet test policy is bounded")
}

fn object() -> Object {
    let control_policy_hash =
        commit(DomainTag::CANONICAL_VALUE, &policy()).expect("test policy commits");
    Object::new(ObjectFields {
        object_id: object_id(),
        object_version: 7,
        type_id: digest(0x11),
        owner: ObjectOwner::Principal(sender()),
        control_policy_hash,
        use_policy_hash: digest(0x12),
        disclosure_policy_hash: digest(0x13),
        upgrade_policy_hash: digest(0x14),
        package_id: None,
        value_root: digest(0x15),
        public_value: None,
        lease_expiry_epoch: 100,
        storage_deposit: 1_000,
        flags: ObjectFlags::TRANSFERABLE.union(ObjectFlags::LINEAR),
    })
    .expect("devnet test object is canonical")
}

fn transaction(height: u64, new_owner: ObjectOwner) -> TransferTransaction {
    let input = ObjectVersionRef::new(object_id(), 7);
    let manifest = AccessManifest::new(AccessManifestFields {
        exact_reads: vec![],
        exact_writes: vec![input],
        immutable_reads: vec![],
        creation_namespaces: vec![],
        maximum_created_objects: 0,
        maximum_dynamic_reads: 0,
        dynamic_read_policy: None,
    })
    .expect("devnet test manifest is canonical");
    let request = PolicyRequest::new(PolicyRequestFields {
        actor: ActorBinding::Principal(sender()),
        action: TRANSFER_OBJECT_ACTION_ID,
        resource: object_id(),
        height,
        value: 0,
        freeze_state: FreezeState::Active,
        declared_purpose: None,
        credential_schemas: vec![],
        capabilities: vec![],
        approvals: vec![],
    })
    .expect("devnet test request is canonical");
    TransferTransaction::new(
        height,
        manifest,
        vec![TransferCommand::new(input, new_owner, policy(), request)],
    )
    .expect("devnet test transaction is canonical")
}

fn prices() -> ResourcePrices {
    ResourcePrices::new(1, 2, 3, 4, 5, 1)
}

fn resources(encoded_bytes: u64) -> ResourceVector {
    ResourceVector::new(100, 1, 1, 0, 0, encoded_bytes)
}

fn envelope(
    ticket_byte: u8,
    sequence: u64,
    maximum_resources: ResourceVector,
    new_owner: ObjectOwner,
    authorization_byte: u8,
) -> ActionEnvelope {
    let payload = transaction(1, new_owner);
    let payload_commitment = commit(DomainTag::CANONICAL_VALUE, &payload).expect("payload commits");
    let fee_ticket = FeeTicket::new(
        ObjectId::new(digest(ticket_byte)),
        PrincipalId::new(digest(0x03)),
        3_000_000,
        10,
        u64::from(ticket_byte),
        resources(2_000_000),
    )
    .expect("devnet test ticket is valid");
    ActionEnvelope::new(
        ACTION_PROTOCOL_VERSION,
        chain_id(),
        sender(),
        fee_ticket,
        0,
        sequence,
        ValidityInterval::new(1, 10).expect("devnet validity is ordered"),
        maximum_resources,
        payload_commitment,
        payload,
        digest(authorization_byte),
    )
    .expect("devnet test envelope is valid")
}

fn genesis() -> ChainState {
    ChainState::genesis(
        chain_id(),
        ObjectState::new(vec![object()]).expect("genesis objects are ordered"),
        vec![NonceChannel::new(sender(), 0, 5)],
        prices(),
    )
    .expect("devnet genesis is valid")
}

fn block(state: &ChainState, actions: Vec<ActionEnvelope>) -> DevnetBlock {
    let pre_state = commit_objects(state.objects().objects()).expect("pre-state commits");
    DevnetBlock::new(chain_id(), 1, Digest384::ZERO, pre_state, actions)
        .expect("test block is bounded")
}

#[test]
fn successful_action_advances_chain_object_nonce_ticket_and_roots() {
    let state = genesis();
    let action = envelope(0x20, 5, resources(2_000_000), ObjectOwner::Shielded(digest(0x30)), 0x40);
    let candidate = block(&state, vec![action]);
    let output = apply_block(&state, &candidate).expect("valid block applies");
    assert_eq!(output.state().height(), 1);
    assert_eq!(output.state().nonce_channels()[0].next_sequence(), 6);
    assert_eq!(output.state().used_fee_tickets(), &[ObjectId::new(digest(0x20))]);
    let updated = output.state().objects().find(object_id()).expect("object remains");
    assert_eq!(updated.object_version(), 8);
    assert_eq!(updated.owner(), ObjectOwner::Shielded(digest(0x30)));
    assert_ne!(output.receipt().pre_state(), output.receipt().post_state());
    assert_eq!(output.receipt().action_receipts().len(), 1);
    assert!(matches!(
        output.receipt().action_receipts()[0].outcome(),
        ActionOutcome::Transition(receipt) if receipt.result() == ReceiptResult::Success
    ));

    let bytes = encode_envelope(output.receipt()).expect("block receipt encodes");
    assert_eq!(decode_envelope(&bytes), Ok(output.receipt().clone()));
    assert_eq!(apply_block(&state, &candidate), Ok(output));
}

#[test]
fn admitted_semantic_failure_consumes_replay_state_but_not_objects() {
    let state = genesis();
    let action = envelope(0x21, 5, resources(2_000_000), ObjectOwner::Principal(sender()), 0x41);
    let output = apply_block(&state, &block(&state, vec![action]))
        .expect("semantic failure is a total action outcome");
    assert_eq!(output.state().objects(), state.objects());
    assert_eq!(output.state().nonce_channels()[0].next_sequence(), 6);
    assert_eq!(output.state().used_fee_tickets().len(), 1);
    assert!(matches!(
        output.receipt().action_receipts()[0].outcome(),
        ActionOutcome::Transition(receipt) if receipt.result() == ReceiptResult::OwnerUnchanged
    ));
}

#[test]
fn resource_limit_failure_rolls_back_objects_and_charges_declared_maximum() {
    let state = genesis();
    let maximum = resources(0);
    let action = envelope(0x22, 5, maximum, ObjectOwner::Shielded(digest(0x32)), 0x42);
    let output = apply_block(&state, &block(&state, vec![action]))
        .expect("resource exhaustion is a total action outcome");
    let receipt = output.receipt().action_receipts()[0];
    assert_eq!(receipt.outcome(), ActionOutcome::ResourceLimitExceeded);
    assert_eq!(receipt.fee_charged(), maximum.checked_charge(prices()).expect("charge fits"));
    assert_eq!(output.state().objects(), state.objects());
    assert_eq!(output.state().nonce_channels()[0].next_sequence(), 6);
    assert_eq!(output.state().used_fee_tickets().len(), 1);
}

#[test]
fn block_header_and_action_admission_errors_publish_nothing() {
    let state = genesis();
    let pre_state = commit_objects(state.objects().objects()).expect("pre-state commits");
    let empty = vec![];
    assert_eq!(
        apply_block(
            &state,
            &DevnetBlock::new(
                ChainId::new(digest(0xff)),
                1,
                Digest384::ZERO,
                pre_state,
                empty.clone(),
            )
            .expect("bounded"),
        ),
        Err(BlockApplyError::WrongChain)
    );
    assert!(matches!(
        apply_block(
            &state,
            &DevnetBlock::new(chain_id(), 2, Digest384::ZERO, pre_state, empty.clone())
                .expect("bounded"),
        ),
        Err(BlockApplyError::UnexpectedHeight { .. })
    ));
    assert_eq!(
        apply_block(
            &state,
            &DevnetBlock::new(chain_id(), 1, digest(1), pre_state, empty.clone()).expect("bounded"),
        ),
        Err(BlockApplyError::WrongParent)
    );
    assert_eq!(
        apply_block(
            &state,
            &DevnetBlock::new(
                chain_id(),
                1,
                Digest384::ZERO,
                StateCommitment::new(digest(2), 1),
                empty,
            )
            .expect("bounded"),
        ),
        Err(BlockApplyError::PreStateMismatch)
    );
}

#[test]
fn nonce_replay_ticket_reuse_and_action_order_are_rejected() {
    let state = genesis();
    let replay = envelope(0x23, 4, resources(2_000_000), ObjectOwner::Shielded(digest(0x33)), 0x43);
    assert_eq!(
        apply_block(&state, &block(&state, vec![replay])),
        Err(BlockApplyError::Nonce {
            index: 0,
            error: NonceAdvanceError::Replay { supplied: 4, expected: 5 },
        })
    );

    let used_ticket = ObjectId::new(digest(0x24));
    let used_state = ChainState::new(
        state.chain_id(),
        state.height(),
        state.head_block_id(),
        state.objects().clone(),
        Vec::from(state.nonce_channels()),
        vec![used_ticket],
        state.resource_prices(),
    )
    .expect("used-ticket fixture is valid");
    let reused = envelope(0x24, 5, resources(2_000_000), ObjectOwner::Shielded(digest(0x34)), 0x44);
    assert_eq!(
        apply_block(&used_state, &block(&used_state, vec![reused])),
        Err(BlockApplyError::FeeTicketAlreadyUsed { index: 0 })
    );

    let first = envelope(0x25, 5, resources(2_000_000), ObjectOwner::Shielded(digest(0x35)), 0x45);
    let second = envelope(0x26, 6, resources(2_000_000), ObjectOwner::Shielded(digest(0x36)), 0x46);
    let mut descending = vec![first, second];
    descending.sort_by_key(|action| action_id(action).expect("action commits"));
    descending.reverse();
    assert_eq!(
        apply_block(&state, &block(&state, descending)),
        Err(BlockApplyError::ActionsNotStrictlyIncreasing { index: 1 })
    );
}

#[test]
fn empty_blocks_advance_deterministically() {
    let state = ChainState::genesis(
        chain_id(),
        ObjectState::new(vec![]).expect("empty state"),
        vec![],
        prices(),
    )
    .expect("empty genesis");
    let output = apply_block(&state, &block(&state, vec![])).expect("empty block applies");
    assert_eq!(output.state().height(), 1);
    assert!(output.receipt().action_receipts().is_empty());
    assert_eq!(output.receipt().pre_state(), output.receipt().post_state());
}

#[test]
fn published_block_receipt_body_bound_is_exact() {
    let state = StateCommitment::new(digest(0x70), u64::MAX);
    let transition = TransitionReceipt::new(
        ReceiptResult::AuthorizationDenied,
        Some(0),
        0,
        0,
        digest(0x71),
        digest(0x71),
    )
    .expect("maximum failure receipt shape is valid");
    let action = ActionReceipt::new(
        TransactionId::new(digest(0x72)),
        ActionOutcome::Transition(transition),
        ResourceVector::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        u128::MAX,
        u64::MAX,
        state,
    );
    let receipt = BlockReceipt::new(digest(0x73), u64::MAX, state, state, vec![action; 32])
        .expect("maximum block receipt is bounded");
    assert_eq!(
        encode_body(&receipt).expect("maximum block receipt encodes").len(),
        BlockReceipt::MAX_ENCODED_LEN
    );
}
