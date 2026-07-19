extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_policy_kernel::{
    APL_LANGUAGE_VERSION, ActorBinding, PolicyEffect, PolicyObligation, PolicyRequest,
    PolicyRequestFields, PolicyRule, PolicySet,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    AccessManifest, AccessManifestFields, ActionId, Digest384, FreezeState, Object, ObjectFields,
    ObjectFlags, ObjectId, ObjectOwner, ObjectVersionRef, PrincipalId,
};

use crate::{
    ObjectState, ReceiptResult, TRANSFER_OBJECT_ACTION_ID, TransferCommand, TransferTransaction,
    TransferTransactionError, TransitionReceipt, apply_transfer_transaction,
};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn policy(obligations: Vec<PolicyObligation>) -> PolicySet {
    PolicySet::new(
        APL_LANGUAGE_VERSION,
        vec![
            PolicyRule::new(PolicyEffect::Permit, vec![], obligations).expect("valid permit rule"),
        ],
    )
    .expect("valid policy")
}

fn deny_policy() -> PolicySet {
    PolicySet::new(APL_LANGUAGE_VERSION, vec![]).expect("empty policy is valid")
}

fn object(
    object_byte: u8,
    version: u64,
    control_policy: &PolicySet,
    owner: ObjectOwner,
    flags: ObjectFlags,
) -> Object {
    let control_policy_hash = commit(DomainTag::CANONICAL_VALUE, control_policy)
        .expect("bounded policy commitment encodes");
    Object::new(ObjectFields {
        object_id: ObjectId::new(digest(object_byte)),
        object_version: version,
        type_id: digest(0x20),
        owner,
        control_policy_hash,
        use_policy_hash: digest(0x31),
        disclosure_policy_hash: digest(0x32),
        upgrade_policy_hash: digest(0x33),
        package_id: None,
        value_root: digest(0x40),
        public_value: Some(vec![object_byte, 1, 2, 3]),
        lease_expiry_epoch: 100,
        storage_deposit: 500,
        flags,
    })
    .expect("test object is canonical")
}

fn request(object_id: ObjectId, height: u64, action: ActionId) -> PolicyRequest {
    PolicyRequest::new(PolicyRequestFields {
        actor: ActorBinding::Principal(PrincipalId::new(digest(0x50))),
        action,
        resource: object_id,
        height,
        value: 0,
        freeze_state: FreezeState::Active,
        declared_purpose: None,
        credential_schemas: vec![],
        capabilities: vec![],
        approvals: vec![],
    })
    .expect("empty fact sets are canonical")
}

fn command(
    object_id: ObjectId,
    version: u64,
    control_policy: PolicySet,
    height: u64,
    action: ActionId,
    new_owner: ObjectOwner,
) -> TransferCommand {
    TransferCommand::new(
        ObjectVersionRef::new(object_id, version),
        new_owner,
        control_policy,
        request(object_id, height, action),
    )
}

fn manifest(writes: Vec<ObjectVersionRef>) -> AccessManifest {
    AccessManifest::new(AccessManifestFields {
        exact_reads: vec![],
        exact_writes: writes,
        immutable_reads: vec![],
        creation_namespaces: vec![],
        maximum_created_objects: 0,
        maximum_dynamic_reads: 0,
        dynamic_read_policy: None,
    })
    .expect("write references are canonical")
}

fn transaction(
    height: u64,
    writes: Vec<ObjectVersionRef>,
    commands: Vec<TransferCommand>,
) -> TransferTransaction {
    TransferTransaction::new(height, manifest(writes), commands).expect("canonical transaction")
}

#[test]
fn successful_batch_advances_every_object_once_and_commits_the_result() {
    let permit = policy(vec![]);
    let first = object(
        0x10,
        7,
        &permit,
        ObjectOwner::Principal(PrincipalId::new(digest(0x50))),
        ObjectFlags::TRANSFERABLE,
    );
    let second = object(0x11, 9, &permit, ObjectOwner::Shared, ObjectFlags::TRANSFERABLE);
    let first_ref = ObjectVersionRef::new(first.object_id(), 7);
    let second_ref = ObjectVersionRef::new(second.object_id(), 9);
    let state = ObjectState::new(vec![first.clone(), second.clone()]).expect("ordered state");
    let tx = transaction(
        42,
        vec![first_ref, second_ref],
        vec![
            command(
                first.object_id(),
                7,
                permit.clone(),
                42,
                TRANSFER_OBJECT_ACTION_ID,
                ObjectOwner::Shared,
            ),
            command(
                second.object_id(),
                9,
                permit,
                42,
                TRANSFER_OBJECT_ACTION_ID,
                ObjectOwner::Shielded(digest(0x60)),
            ),
        ],
    );

    let output = apply_transfer_transaction(&state, &tx).expect("transition is total");
    assert_eq!(output.receipt().result(), ReceiptResult::Success);
    assert_eq!(output.receipt().objects_updated(), 2);
    assert_eq!(output.receipt().policy_steps(), 2);
    assert_eq!(output.state().find(first.object_id()).expect("first").object_version(), 8);
    assert_eq!(output.state().find(second.object_id()).expect("second").object_version(), 10);
    assert_ne!(output.receipt().pre_state_commitment(), output.receipt().post_state_commitment());
}

#[test]
fn failure_after_a_scratch_update_publishes_the_exact_pre_state() {
    let permit = policy(vec![]);
    let first = object(0x10, 7, &permit, ObjectOwner::Shared, ObjectFlags::TRANSFERABLE);
    let second = object(0x11, 9, &permit, ObjectOwner::Shared, ObjectFlags::TRANSFERABLE);
    let first_ref = ObjectVersionRef::new(first.object_id(), 7);
    let stale_second_ref = ObjectVersionRef::new(second.object_id(), 8);
    let state = ObjectState::new(vec![first.clone(), second.clone()]).expect("ordered state");
    let tx = transaction(
        42,
        vec![first_ref, stale_second_ref],
        vec![
            command(
                first.object_id(),
                7,
                permit.clone(),
                42,
                TRANSFER_OBJECT_ACTION_ID,
                ObjectOwner::Shielded(digest(0x61)),
            ),
            command(
                second.object_id(),
                8,
                permit,
                42,
                TRANSFER_OBJECT_ACTION_ID,
                ObjectOwner::Shielded(digest(0x62)),
            ),
        ],
    );

    let output = apply_transfer_transaction(&state, &tx).expect("semantic failure is a receipt");
    assert_eq!(output.receipt().result(), ReceiptResult::StaleObjectVersion);
    assert_eq!(output.receipt().failed_command(), Some(1));
    assert_eq!(output.receipt().objects_updated(), 0);
    assert_eq!(output.receipt().policy_steps(), 1);
    assert_eq!(output.state(), &state);
    assert_eq!(output.receipt().pre_state_commitment(), output.receipt().post_state_commitment());
}

#[test]
fn request_manifest_policy_and_obligation_failures_are_total() {
    let permit = policy(vec![]);
    let value = object(0x10, 7, &permit, ObjectOwner::Shared, ObjectFlags::TRANSFERABLE);
    let state = ObjectState::new(vec![value.clone()]).expect("ordered state");
    let reference = ObjectVersionRef::new(value.object_id(), 7);

    let wrong_action = ActionId::new(digest(0xff));
    let tx = transaction(
        42,
        vec![reference],
        vec![command(
            value.object_id(),
            7,
            permit.clone(),
            42,
            wrong_action,
            ObjectOwner::Shielded(digest(0x60)),
        )],
    );
    let output = apply_transfer_transaction(&state, &tx).expect("failure receipt");
    assert_eq!(output.receipt().result(), ReceiptResult::RequestContextMismatch);
    assert_eq!(output.state(), &state);

    let tx = transaction(
        42,
        vec![],
        vec![command(
            value.object_id(),
            7,
            permit.clone(),
            42,
            TRANSFER_OBJECT_ACTION_ID,
            ObjectOwner::Shielded(digest(0x60)),
        )],
    );
    let output = apply_transfer_transaction(&state, &tx).expect("failure receipt");
    assert_eq!(output.receipt().result(), ReceiptResult::AccessManifestViolation);

    let wrong_policy = deny_policy();
    let tx = transaction(
        42,
        vec![reference],
        vec![command(
            value.object_id(),
            7,
            wrong_policy,
            42,
            TRANSFER_OBJECT_ACTION_ID,
            ObjectOwner::Shielded(digest(0x60)),
        )],
    );
    let output = apply_transfer_transaction(&state, &tx).expect("failure receipt");
    assert_eq!(output.receipt().result(), ReceiptResult::ControlPolicyMismatch);

    let obligation_policy = policy(vec![PolicyObligation::DelaySettlementUntil(50)]);
    let obligated =
        object(0x10, 7, &obligation_policy, ObjectOwner::Shared, ObjectFlags::TRANSFERABLE);
    let obligated_state = ObjectState::new(vec![obligated.clone()]).expect("ordered state");
    let tx = transaction(
        42,
        vec![reference],
        vec![command(
            obligated.object_id(),
            7,
            obligation_policy,
            42,
            TRANSFER_OBJECT_ACTION_ID,
            ObjectOwner::Shielded(digest(0x60)),
        )],
    );
    let output = apply_transfer_transaction(&obligated_state, &tx).expect("failure receipt");
    assert_eq!(output.receipt().result(), ReceiptResult::UnsupportedObligation);
    assert_eq!(output.state(), &obligated_state);
}

#[test]
fn committed_deny_and_object_transfer_failures_select_typed_receipts() {
    let denied = deny_policy();
    let denied_object = object(0x10, 7, &denied, ObjectOwner::Shared, ObjectFlags::TRANSFERABLE);
    let reference = ObjectVersionRef::new(denied_object.object_id(), 7);
    let state = ObjectState::new(vec![denied_object.clone()]).expect("ordered state");
    let tx = transaction(
        42,
        vec![reference],
        vec![command(
            denied_object.object_id(),
            7,
            denied,
            42,
            TRANSFER_OBJECT_ACTION_ID,
            ObjectOwner::Shielded(digest(0x60)),
        )],
    );
    let output = apply_transfer_transaction(&state, &tx).expect("failure receipt");
    assert_eq!(output.receipt().result(), ReceiptResult::AuthorizationDenied);

    let permit = policy(vec![]);
    for (owner, flags, new_owner, expected) in [
        (
            ObjectOwner::Immutable,
            ObjectFlags::NONE,
            ObjectOwner::Shared,
            ReceiptResult::ImmutableObject,
        ),
        (
            ObjectOwner::Shared,
            ObjectFlags::NONE,
            ObjectOwner::Shielded(digest(0x60)),
            ReceiptResult::TransferDisabled,
        ),
        (
            ObjectOwner::Shared,
            ObjectFlags::TRANSFERABLE,
            ObjectOwner::Shared,
            ReceiptResult::OwnerUnchanged,
        ),
    ] {
        let value = object(0x10, 7, &permit, owner, flags);
        let reference = ObjectVersionRef::new(value.object_id(), 7);
        let state = ObjectState::new(vec![value.clone()]).expect("ordered state");
        let tx = transaction(
            42,
            vec![reference],
            vec![command(
                value.object_id(),
                7,
                permit.clone(),
                42,
                TRANSFER_OBJECT_ACTION_ID,
                new_owner,
            )],
        );
        let output = apply_transfer_transaction(&state, &tx).expect("failure receipt");
        assert_eq!(output.receipt().result(), expected);
        assert_eq!(output.state(), &state);
    }
}

#[test]
fn missing_and_exhausted_objects_are_semantic_failures() {
    let permit = policy(vec![]);
    let missing_id = ObjectId::new(digest(0x10));
    let reference = ObjectVersionRef::new(missing_id, 7);
    let empty_state = ObjectState::new(vec![]).expect("empty state is canonical");
    let tx = transaction(
        42,
        vec![reference],
        vec![command(
            missing_id,
            7,
            permit.clone(),
            42,
            TRANSFER_OBJECT_ACTION_ID,
            ObjectOwner::Shared,
        )],
    );
    let output = apply_transfer_transaction(&empty_state, &tx).expect("failure receipt");
    assert_eq!(output.receipt().result(), ReceiptResult::ObjectNotFound);
    assert_eq!(output.state(), &empty_state);

    let exhausted = object(0x10, u64::MAX, &permit, ObjectOwner::Shared, ObjectFlags::TRANSFERABLE);
    let reference = ObjectVersionRef::new(exhausted.object_id(), u64::MAX);
    let state = ObjectState::new(vec![exhausted.clone()]).expect("ordered state");
    let tx = transaction(
        42,
        vec![reference],
        vec![command(
            exhausted.object_id(),
            u64::MAX,
            permit,
            42,
            TRANSFER_OBJECT_ACTION_ID,
            ObjectOwner::Shielded(digest(0x60)),
        )],
    );
    let output = apply_transfer_transaction(&state, &tx).expect("failure receipt");
    assert_eq!(output.receipt().result(), ReceiptResult::VersionExhausted);
    assert_eq!(output.state(), &state);
}

#[test]
fn receipt_shapes_enforce_atomic_publication() {
    let pre = digest(0x10);
    let post = digest(0x20);
    assert!(TransitionReceipt::new(ReceiptResult::Success, Some(0), 1, 0, pre, post).is_err());
    assert!(
        TransitionReceipt::new(ReceiptResult::AccessManifestViolation, Some(0), 0, 0, pre, post,)
            .is_err()
    );
}

#[test]
fn canonical_state_transaction_and_receipt_round_trip() {
    let permit = policy(vec![]);
    let value = object(0x10, 7, &permit, ObjectOwner::Shared, ObjectFlags::TRANSFERABLE);
    let reference = ObjectVersionRef::new(value.object_id(), 7);
    let state = ObjectState::new(vec![value.clone()]).expect("ordered state");
    let tx = transaction(
        42,
        vec![reference],
        vec![command(
            value.object_id(),
            7,
            permit,
            42,
            TRANSFER_OBJECT_ACTION_ID,
            ObjectOwner::Shielded(digest(0x60)),
        )],
    );
    let output = apply_transfer_transaction(&state, &tx).expect("successful transition");

    let state_bytes = encode_envelope(&state).expect("state fits its bound");
    assert_eq!(decode_envelope(&state_bytes), Ok(state));
    let tx_bytes = encode_envelope(&tx).expect("transaction fits its bound");
    assert_eq!(decode_envelope(&tx_bytes), Ok(tx));
    let receipt_bytes = encode_envelope(&output.receipt()).expect("receipt fits its bound");
    assert_eq!(decode_envelope::<TransitionReceipt>(&receipt_bytes), Ok(output.receipt()));
}

#[test]
fn transfer_commands_must_be_nonempty_and_strictly_ordered() {
    assert!(matches!(
        TransferTransaction::new(42, manifest(vec![]), vec![]),
        Err(TransferTransactionError::EmptyCommands)
    ));

    let permit = policy(vec![]);
    let high = ObjectId::new(digest(0x20));
    let low = ObjectId::new(digest(0x10));
    let commands = vec![
        command(high, 1, permit.clone(), 42, TRANSFER_OBJECT_ACTION_ID, ObjectOwner::Shared),
        command(low, 1, permit, 42, TRANSFER_OBJECT_ACTION_ID, ObjectOwner::Shared),
    ];
    assert_eq!(
        TransferTransaction::new(42, manifest(vec![]), commands),
        Err(TransferTransactionError::CommandsNotStrictlyIncreasing)
    );
}
