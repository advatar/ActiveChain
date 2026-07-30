extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use activechain_action_kernel::{
    ACTION_PROTOCOL_VERSION, ActionEnvelope, FeeTicket, NonceChannel, ResourcePrices,
    ResourceVector, ValidityInterval, action_id,
};
use activechain_canonical_codec::{
    CanonicalEncode, CanonicalType, Encoder, decode_envelope, encode_body, encode_envelope,
};
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
    FeeAccount, MAX_BLOCK_ACTIONS, MAX_FEE_TICKET_LIFETIME, MAX_USED_FEE_TICKETS, UsedFeeTicket,
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
    envelope_at(
        ticket_byte,
        sequence,
        sequence,
        1,
        1,
        8,
        maximum_resources,
        new_owner,
        authorization_byte,
    )
}

#[allow(clippy::too_many_arguments)]
fn envelope_at(
    ticket_byte: u8,
    ticket_nonce: u64,
    sequence: u64,
    height: u64,
    valid_from: u64,
    valid_until: u64,
    maximum_resources: ResourceVector,
    new_owner: ObjectOwner,
    authorization_byte: u8,
) -> ActionEnvelope {
    let payload = transaction(height, new_owner);
    let payload_commitment = commit(DomainTag::CANONICAL_VALUE, &payload).expect("payload commits");
    let fee_ticket = FeeTicket::new(
        ObjectId::new(digest(ticket_byte)),
        sender(),
        3_000_000,
        valid_until,
        ticket_nonce,
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
        ValidityInterval::new(valid_from, valid_until).expect("devnet validity is ordered"),
        maximum_resources,
        payload_commitment,
        payload,
        digest(authorization_byte),
    )
    .expect("devnet test envelope is valid")
}

fn genesis() -> ChainState {
    ChainState::genesis_with_fee_accounts(
        chain_id(),
        ObjectState::new(vec![object()]).expect("genesis objects are ordered"),
        vec![NonceChannel::new(sender(), 0, 5)],
        vec![FeeAccount::new(sender(), 100_000_000, 5)],
        prices(),
    )
    .expect("devnet genesis is valid")
}

fn block(state: &ChainState, actions: Vec<ActionEnvelope>) -> DevnetBlock {
    block_at(state, 1, actions)
}

fn block_at(state: &ChainState, height: u64, actions: Vec<ActionEnvelope>) -> DevnetBlock {
    let pre_state = commit_objects(state.objects().objects()).expect("pre-state commits");
    let pre_chain_state =
        commit(DomainTag::CANONICAL_VALUE, state).expect("complete pre-state commits");
    DevnetBlock::new(chain_id(), height, state.head_block_id(), pre_state, pre_chain_state, actions)
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
    assert_eq!(
        output.state().used_fee_tickets(),
        &[UsedFeeTicket::new(ObjectId::new(digest(0x20)), 8)]
    );
    assert_eq!(output.state().fee_accounts()[0].next_nonce(), 6);
    assert!(output.state().fee_accounts()[0].balance() < 100_000_000);
    let updated = output.state().objects().find(object_id()).expect("object remains");
    assert_eq!(updated.object_version(), 8);
    assert_eq!(updated.owner(), ObjectOwner::Shielded(digest(0x30)));
    assert_ne!(output.receipt().pre_state(), output.receipt().post_state());
    assert_eq!(output.receipt().pre_chain_state(), state.commitment().unwrap());
    assert_eq!(output.receipt().post_chain_state(), output.state().commitment().unwrap());
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
    assert_eq!(receipt.fee_charged(), maximum.checked_charge(prices()).expect("charge fits") + 1);
    assert_eq!(output.state().objects(), state.objects());
    assert_eq!(output.state().nonce_channels()[0].next_sequence(), 6);
    assert_eq!(output.state().used_fee_tickets().len(), 1);
}

#[test]
fn block_header_and_action_admission_errors_publish_nothing() {
    let state = genesis();
    let pre_state = commit_objects(state.objects().objects()).expect("pre-state commits");
    let pre_chain_state = commit(DomainTag::CANONICAL_VALUE, &state).unwrap();
    let empty = vec![];
    assert_eq!(
        apply_block(
            &state,
            &DevnetBlock::new(
                ChainId::new(digest(0xff)),
                1,
                Digest384::ZERO,
                pre_state,
                pre_chain_state,
                empty.clone(),
            )
            .expect("bounded"),
        ),
        Err(BlockApplyError::WrongChain)
    );
    assert!(matches!(
        apply_block(
            &state,
            &DevnetBlock::new(
                chain_id(),
                2,
                Digest384::ZERO,
                pre_state,
                pre_chain_state,
                empty.clone(),
            )
            .expect("bounded"),
        ),
        Err(BlockApplyError::UnexpectedHeight { .. })
    ));
    assert_eq!(
        apply_block(
            &state,
            &DevnetBlock::new(chain_id(), 1, digest(1), pre_state, pre_chain_state, empty.clone(),)
                .expect("bounded"),
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
                pre_chain_state,
                empty,
            )
            .expect("bounded"),
        ),
        Err(BlockApplyError::PreStateMismatch)
    );
    assert_eq!(
        apply_block(
            &state,
            &DevnetBlock::new(chain_id(), 1, Digest384::ZERO, pre_state, digest(0xfe), vec![],)
                .expect("bounded"),
        ),
        Err(BlockApplyError::PreChainStateMismatch)
    );
}

#[test]
fn nonce_replay_ticket_reuse_and_action_order_are_rejected() {
    let state = genesis();
    let replay = envelope(0x23, 4, resources(2_000_000), ObjectOwner::Shielded(digest(0x33)), 0x43);
    assert_eq!(
        apply_block(&state, &block(&state, vec![replay])),
        Err(BlockApplyError::FeeTicketNonceReplay { index: 0, supplied: 4, expected: 5 })
    );

    let used_ticket = ObjectId::new(digest(0x24));
    let used_state = ChainState::new(
        state.chain_id(),
        state.height(),
        state.head_block_id(),
        state.objects().clone(),
        Vec::from(state.nonce_channels()),
        Vec::from(state.fee_accounts()),
        vec![UsedFeeTicket::new(used_ticket, 7)],
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
fn fee_ticket_requires_funding_exact_nonce_and_bounded_validity() {
    let funded = genesis();
    let future = envelope_at(
        0x4e,
        5,
        5,
        2,
        2,
        2,
        resources(2_000_000),
        ObjectOwner::Shielded(digest(0x5e)),
        0x6e,
    );
    assert_eq!(
        apply_block(&funded, &block(&funded, vec![future])),
        Err(BlockApplyError::ActionOutsideValidity { index: 0 })
    );

    let expired_payload = transaction(1, ObjectOwner::Shielded(digest(0x5f)));
    let expired_ticket = FeeTicket::new(
        ObjectId::new(digest(0x4f)),
        sender(),
        3_000_000,
        0,
        5,
        resources(2_000_000),
    )
    .unwrap();
    let expired = ActionEnvelope::new(
        ACTION_PROTOCOL_VERSION,
        chain_id(),
        sender(),
        expired_ticket,
        0,
        5,
        ValidityInterval::new(1, 1).unwrap(),
        resources(2_000_000),
        commit(DomainTag::CANONICAL_VALUE, &expired_payload).unwrap(),
        expired_payload,
        digest(0x6f),
    )
    .unwrap();
    assert_eq!(
        apply_block(&funded, &block(&funded, vec![expired])),
        Err(BlockApplyError::FeeTicketExpired { index: 0 })
    );

    let payload = transaction(1, ObjectOwner::Shielded(digest(0x60)));
    let forged_ticket = FeeTicket::new(
        ObjectId::new(digest(0x50)),
        PrincipalId::new(digest(0x03)),
        3_000_000,
        8,
        5,
        resources(2_000_000),
    )
    .expect("forged-payer fixture is structurally valid");
    let forged = ActionEnvelope::new(
        ACTION_PROTOCOL_VERSION,
        chain_id(),
        sender(),
        forged_ticket,
        0,
        5,
        ValidityInterval::new(1, 8).unwrap(),
        resources(2_000_000),
        commit(DomainTag::CANONICAL_VALUE, &payload).unwrap(),
        payload,
        digest(0x70),
    )
    .expect("payer mismatch is an admission concern");
    assert_eq!(
        apply_block(&funded, &block(&funded, vec![forged])),
        Err(BlockApplyError::FeePayerDoesNotMatchSender { index: 0 })
    );

    let missing = ChainState::genesis(
        chain_id(),
        funded.objects().clone(),
        Vec::from(funded.nonce_channels()),
        prices(),
    )
    .expect("unfunded state is canonical");
    let action = envelope(0x51, 5, resources(2_000_000), ObjectOwner::Shielded(digest(0x61)), 0x71);
    assert_eq!(
        apply_block(&missing, &block(&missing, vec![action.clone()])),
        Err(BlockApplyError::MissingFeeAccount { index: 0 })
    );

    let gap = envelope_at(
        0x52,
        6,
        5,
        1,
        1,
        8,
        resources(2_000_000),
        ObjectOwner::Shielded(digest(0x62)),
        0x72,
    );
    assert_eq!(
        apply_block(&funded, &block(&funded, vec![gap])),
        Err(BlockApplyError::FeeTicketNonceGap { index: 0, supplied: 6, expected: 5 })
    );

    let too_long = envelope_at(
        0x53,
        5,
        5,
        1,
        1,
        9,
        resources(2_000_000),
        ObjectOwner::Shielded(digest(0x63)),
        0x73,
    );
    assert_eq!(
        apply_block(&funded, &block(&funded, vec![too_long])),
        Err(BlockApplyError::FeeTicketValidityTooLong { index: 0 })
    );

    let poor = ChainState::genesis_with_fee_accounts(
        chain_id(),
        funded.objects().clone(),
        Vec::from(funded.nonce_channels()),
        vec![FeeAccount::new(sender(), 1, 5)],
        prices(),
    )
    .expect("underfunded state is canonical");
    assert_eq!(
        apply_block(&poor, &block(&poor, vec![action])),
        Err(BlockApplyError::InsufficientFeeBalance { index: 0 })
    );
}

#[test]
fn expired_ticket_records_prune_but_nonce_still_rejects_replay_after_restart() {
    let initial = genesis();
    let first = envelope(0x54, 5, resources(2_000_000), ObjectOwner::Shielded(digest(0x64)), 0x74);
    let output =
        apply_block(&initial, &block(&initial, vec![first])).expect("first action applies");
    let persisted = encode_envelope(output.state()).expect("state snapshot encodes");
    assert_eq!(<ChainState as CanonicalType>::SCHEMA_VERSION, 2);
    let restarted: ChainState = decode_envelope(&persisted).expect("state snapshot decodes");
    let replay = envelope_at(
        0x54,
        5,
        6,
        2,
        2,
        8,
        resources(2_000_000),
        ObjectOwner::Shielded(digest(0x65)),
        0x75,
    );
    assert_eq!(
        apply_block(&restarted, &block_at(&restarted, 2, vec![replay])),
        Err(BlockApplyError::FeeTicketNonceReplay { index: 0, supplied: 5, expected: 6 })
    );

    let prunable = ChainState::new(
        chain_id(),
        8,
        digest(0x80),
        initial.objects().clone(),
        vec![NonceChannel::new(sender(), 0, 6)],
        vec![FeeAccount::new(sender(), 100_000_000, 6)],
        vec![UsedFeeTicket::new(ObjectId::new(digest(0x54)), 8)],
        prices(),
    )
    .expect("last-valid-height record is canonical");
    let next = envelope_at(
        0x55,
        6,
        6,
        9,
        9,
        16,
        resources(2_000_000),
        ObjectOwner::Shielded(digest(0x66)),
        0x76,
    );
    let advanced = apply_block(&prunable, &block_at(&prunable, 9, vec![next]))
        .expect("expired replay record prunes before admission");
    assert_eq!(advanced.state().used_fee_tickets().len(), 1);
    assert_eq!(advanced.state().used_fee_tickets()[0].ticket_id(), ObjectId::new(digest(0x55)));
}

#[test]
fn hostile_saturated_replay_state_fails_closed_without_growth() {
    let initial = genesis();
    let mut records = (0_u16..256)
        .map(|index| {
            let mut bytes = [0_u8; 48];
            bytes[..2].copy_from_slice(&index.to_be_bytes());
            UsedFeeTicket::new(ObjectId::new(Digest384::new(bytes)), 1)
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.ticket_id());
    let saturated = ChainState::new(
        chain_id(),
        0,
        Digest384::ZERO,
        initial.objects().clone(),
        Vec::from(initial.nonce_channels()),
        Vec::from(initial.fee_accounts()),
        records,
        prices(),
    )
    .expect("bounded hostile state is canonical");
    let action = envelope(0x99, 5, resources(2_000_000), ObjectOwner::Shielded(digest(0x69)), 0x79);
    assert_eq!(
        apply_block(&saturated, &block(&saturated, vec![action])),
        Err(BlockApplyError::UsedFeeTicketCapacityExhausted { index: 0 })
    );
    assert_eq!(saturated.used_fee_tickets().len(), 256);
}

#[test]
fn sustained_ticket_traffic_remains_inside_the_derived_replay_bound() {
    assert_eq!(
        MAX_USED_FEE_TICKETS,
        MAX_BLOCK_ACTIONS * (usize::try_from(MAX_FEE_TICKET_LIFETIME).unwrap() + 1)
    );
    let mut state = genesis();
    let opening_balance = state.fee_accounts()[0].balance();
    for height in 1_u64..=16 {
        let sequence = height + 4;
        let action = envelope_at(
            u8::try_from(height % 256).unwrap(),
            sequence,
            sequence,
            height,
            height,
            height + MAX_FEE_TICKET_LIFETIME,
            resources(2_000_000),
            ObjectOwner::Principal(sender()),
            u8::try_from((height + 17) % 256).unwrap(),
        );
        state = apply_block(&state, &block_at(&state, height, vec![action]))
            .expect("funded sustained traffic cannot exhaust replay state")
            .state()
            .clone();
        assert!(state.used_fee_tickets().len() <= MAX_USED_FEE_TICKETS);
        assert!(state.used_fee_tickets().iter().all(|ticket| ticket.expires_at() >= height));
    }
    assert_eq!(state.used_fee_tickets().len(), 8);
    assert_eq!(state.fee_accounts()[0].next_nonce(), 21);
    assert!(state.fee_accounts()[0].balance() < opening_balance);
}

fn legacy_state_snapshot(state: &ChainState, used: &[ObjectId]) -> Vec<u8> {
    let mut body = Encoder::new(2_000_000);
    state.chain_id().encode(&mut body).unwrap();
    state.height().encode(&mut body).unwrap();
    state.head_block_id().encode(&mut body).unwrap();
    state.objects().encode(&mut body).unwrap();
    body.write_length(state.nonce_channels().len(), 64).unwrap();
    for channel in state.nonce_channels() {
        channel.encode(&mut body).unwrap();
    }
    body.write_length(used.len(), 256).unwrap();
    for ticket in used {
        ticket.encode(&mut body).unwrap();
    }
    state.resource_prices().encode(&mut body).unwrap();
    let body = body.finish();
    let mut envelope = Encoder::new(body.len() + 16);
    envelope.write_u16(<ChainState as CanonicalType>::TYPE_TAG).unwrap();
    envelope.write_u16(1).unwrap();
    envelope.write_length(body.len(), 2_000_000).unwrap();
    envelope.write_raw(&body).unwrap();
    envelope.finish()
}

#[test]
fn legacy_snapshot_migration_is_explicit_and_fails_closed_with_replay_history() {
    let old = ChainState::genesis(
        chain_id(),
        ObjectState::new(vec![]).expect("empty state"),
        vec![NonceChannel::new(sender(), 0, 5)],
        prices(),
    )
    .expect("legacy-shaped state");
    let accounts = vec![FeeAccount::new(sender(), 50_000, 5)];
    let (migrated, did_migrate) =
        ChainState::decode_snapshot(&legacy_state_snapshot(&old, &[]), accounts.clone())
            .expect("empty legacy replay history migrates");
    assert!(did_migrate);
    assert_eq!(migrated.fee_accounts(), accounts);
    assert!(migrated.used_fee_tickets().is_empty());

    assert!(
        ChainState::decode_snapshot(
            &legacy_state_snapshot(&old, &[ObjectId::new(digest(0xaa))]),
            accounts,
        )
        .is_err()
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
    let receipt = BlockReceipt::new(
        digest(0x73),
        u64::MAX,
        state,
        state,
        digest(0x74),
        digest(0x75),
        vec![action; 32],
    )
    .expect("maximum block receipt is bounded");
    assert_eq!(
        encode_body(&receipt).expect("maximum block receipt encodes").len(),
        BlockReceipt::MAX_ENCODED_LEN
    );
}
