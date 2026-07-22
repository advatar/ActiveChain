extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use activechain_canonical_codec::{decode_envelope, encode_body, encode_envelope};
use activechain_protocol_types::{
    Digest384, Object, ObjectFields, ObjectFlags, ObjectId, ObjectOwner,
};
use proptest::prelude::*;

use crate::hash::empty_hashes;
use crate::{
    MAX_REFERENCE_STATE_OBJECTS, STATE_TREE_ARITY, STATE_TREE_DEPTH, StateProof, StateProofKind,
    StateProofLevel, StateProofUpdateError, StateProofValidationError, StateProofVerificationError,
    StateTreeError, apply_single_key_update, commit_objects, partition_id, path_nibble,
    prove_object, verify_membership, verify_non_membership,
};

fn digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn object_id_with_ends(first: u8, last: u8) -> ObjectId {
    let mut bytes = [0_u8; 48];
    bytes[0] = first;
    bytes[47] = last;
    ObjectId::new(Digest384::new(bytes))
}

fn object(object_id: ObjectId, version: u64) -> Object {
    Object::new(ObjectFields {
        object_id,
        object_version: version,
        type_id: digest(0x20),
        owner: ObjectOwner::Shared,
        control_policy_hash: digest(0x30),
        use_policy_hash: digest(0x31),
        disclosure_policy_hash: digest(0x32),
        upgrade_policy_hash: digest(0x33),
        package_id: None,
        value_root: digest(0x40),
        public_value: None,
        lease_expiry_epoch: 100,
        storage_deposit: 500,
        flags: ObjectFlags::TRANSFERABLE,
    })
    .expect("test object is canonical")
}

#[test]
fn nibble_paths_and_partition_boundaries_are_high_to_low() {
    let key = object_id_with_ends(0xab, 0xcd);
    assert_eq!(path_nibble(key, 0), Some(0x0a));
    assert_eq!(path_nibble(key, 1), Some(0x0b));
    assert_eq!(path_nibble(key, 94), Some(0x0c));
    assert_eq!(path_nibble(key, 95), Some(0x0d));
    assert_eq!(path_nibble(key, STATE_TREE_DEPTH), None);

    let zero = ObjectId::new(Digest384::ZERO);
    assert_eq!(partition_id(zero), 0);
    let maximum = ObjectId::new(Digest384::new([0xff; 48]));
    assert_eq!(partition_id(maximum), 4_095);

    let mut bytes = [0_u8; 48];
    bytes[0] = 0x12;
    bytes[1] = 0x30;
    assert_eq!(partition_id(ObjectId::new(Digest384::new(bytes))), 0x123);
}

#[test]
fn empty_and_multi_object_commitments_are_deterministic_and_canonical() {
    let empty = commit_objects(&[]).expect("empty state commits");
    assert_eq!(empty.object_count(), 0);
    assert_eq!(commit_objects(&[]), Ok(empty));

    let first = object(object_id_with_ends(0x10, 0x00), 1);
    let second = object(object_id_with_ends(0x20, 0x00), 2);
    let ordered = vec![first.clone(), second.clone()];
    let mut independently_constructed = vec![second, first];
    independently_constructed.sort_by_key(Object::object_id);
    assert_eq!(commit_objects(&ordered), commit_objects(&independently_constructed));

    let encoded = encode_envelope(&empty).expect("commitment is fixed size");
    assert_eq!(decode_envelope(&encoded), Ok(empty));
}

#[test]
fn membership_and_non_membership_proofs_verify_and_round_trip() {
    let first = object(object_id_with_ends(0x10, 0x10), 7);
    let second = object(object_id_with_ends(0x10, 0x11), 8);
    let objects = vec![first.clone(), second];
    let commitment = commit_objects(&objects).expect("state commits");

    let member = prove_object(&objects, first.object_id()).expect("member proof generates");
    assert_eq!(member.kind(), StateProofKind::Membership);
    verify_membership(commitment, &first, &member).expect("member proof verifies");

    let absent_id = object_id_with_ends(0x10, 0x12);
    let absent = prove_object(&objects, absent_id).expect("absence proof generates");
    assert_eq!(absent.kind(), StateProofKind::NonMembership);
    verify_non_membership(commitment, absent_id, &absent).expect("absence proof verifies");

    let proof_bytes = encode_envelope(&member).expect("proof fits its bound");
    assert_eq!(decode_envelope(&proof_bytes), Ok(member));
}

#[test]
fn authenticated_single_key_updates_match_full_tree_recomputation() {
    let first = object(object_id_with_ends(0x10, 0x10), 7);
    let second = object(object_id_with_ends(0x20, 0x20), 8);
    let objects = vec![first.clone(), second.clone()];
    let commitment = commit_objects(&objects).expect("state commits");

    let replacement = object(first.object_id(), 9);
    let member_proof = prove_object(&objects, first.object_id()).expect("membership proof");
    let replaced =
        apply_single_key_update(commitment, &member_proof, Some(&first), Some(&replacement))
            .expect("replacement authenticates");
    assert_eq!(replaced, commit_objects(&[replacement.clone(), second.clone()]).unwrap());
    assert_eq!(replaced.object_count(), commitment.object_count());

    let deletion_proof = prove_object(&objects, second.object_id()).expect("deletion proof");
    let deleted = apply_single_key_update(commitment, &deletion_proof, Some(&second), None)
        .expect("deletion authenticates");
    assert_eq!(deleted, commit_objects(core::slice::from_ref(&first)).unwrap());
    assert_eq!(deleted.object_count(), commitment.object_count() - 1);

    let inserted_object = object(object_id_with_ends(0x30, 0x30), 10);
    let insertion_proof =
        prove_object(&objects, inserted_object.object_id()).expect("non-membership proof");
    let inserted =
        apply_single_key_update(commitment, &insertion_proof, None, Some(&inserted_object))
            .expect("insertion authenticates");
    assert_eq!(inserted, commit_objects(&[first, second, inserted_object]).unwrap());
    assert_eq!(inserted.object_count(), commitment.object_count() + 1);

    let wrong_key = object(object_id_with_ends(0x40, 0x40), 1);
    assert_eq!(
        apply_single_key_update(
            commitment,
            &member_proof,
            Some(&object(object_id_with_ends(0x10, 0x10), 7)),
            Some(&wrong_key)
        ),
        Err(StateProofUpdateError::AfterObjectIdMismatch)
    );
}

#[test]
fn proof_kind_key_leaf_and_sibling_tampering_are_rejected() {
    let first = object(object_id_with_ends(0x10, 0x10), 7);
    let second = object(object_id_with_ends(0x10, 0x11), 8);
    let objects = vec![first.clone(), second];
    let commitment = commit_objects(&objects).expect("state commits");
    let proof = prove_object(&objects, first.object_id()).expect("proof generates");

    assert_eq!(
        verify_non_membership(commitment, first.object_id(), &proof),
        Err(StateProofVerificationError::WrongProofKind)
    );
    let other = object(object_id_with_ends(0x10, 0x12), 7);
    assert_eq!(
        verify_membership(commitment, &other, &proof),
        Err(StateProofVerificationError::ObjectIdMismatch)
    );
    let changed = object(first.object_id(), 9);
    assert_eq!(
        verify_membership(commitment, &changed, &proof),
        Err(StateProofVerificationError::RootMismatch)
    );

    let mut levels = proof.levels().to_vec();
    let last = &levels[STATE_TREE_DEPTH - 1];
    let mut siblings = last.siblings().to_vec();
    let mut bytes = siblings[0].into_bytes();
    bytes[0] ^= 1;
    siblings[0] = Digest384::new(bytes);
    levels[STATE_TREE_DEPTH - 1] =
        StateProofLevel::new(last.sibling_bitmap(), siblings).expect("same bitmap count");
    let tampered = StateProof::new(StateProofKind::Membership, first.object_id(), levels)
        .expect("tampered hash is structurally canonical");
    assert_eq!(
        verify_membership(commitment, &first, &tampered),
        Err(StateProofVerificationError::RootMismatch)
    );
}

#[test]
fn proof_constructor_rejects_path_bits_and_explicit_defaults() {
    let object_id = object_id_with_ends(0x10, 0x10);
    let empty_level = StateProofLevel::new(0, vec![]).expect("empty level");
    let mut levels = vec![empty_level; STATE_TREE_DEPTH];
    let path_child = usize::from(path_nibble(object_id, 0).expect("valid depth"));
    levels[0] =
        StateProofLevel::new(1_u16 << path_child, vec![digest(0x70)]).expect("one bitmap value");
    assert_eq!(
        StateProof::new(StateProofKind::NonMembership, object_id, levels),
        Err(StateProofValidationError::PathChildEncoded { depth: 0 })
    );

    let mut levels = vec![StateProofLevel::new(0, vec![]).expect("empty level"); STATE_TREE_DEPTH];
    let sibling_child = (path_child + 1) % STATE_TREE_ARITY;
    levels[0] = StateProofLevel::new(1_u16 << sibling_child, vec![empty_hashes()[1]])
        .expect("one bitmap value");
    assert_eq!(
        StateProof::new(StateProofKind::NonMembership, object_id, levels),
        Err(StateProofValidationError::DefaultSiblingEncoded { depth: 0 })
    );
}

#[test]
fn object_input_order_uniqueness_and_bounds_are_enforced() {
    let low = object(object_id_with_ends(0x10, 0), 0);
    let high = object(object_id_with_ends(0x20, 0), 0);
    assert_eq!(commit_objects(&[high, low]), Err(StateTreeError::ObjectsNotStrictlyIncreasing));

    let too_many: Vec<_> = (0_u8..=64).map(|byte| object(ObjectId::new(digest(byte)), 0)).collect();
    assert_eq!(too_many.len(), MAX_REFERENCE_STATE_OBJECTS + 1);
    assert!(matches!(commit_objects(&too_many), Err(StateTreeError::TooManyObjects { .. })));
}

#[test]
fn worst_case_proof_body_matches_the_published_bound() {
    let object_id = ObjectId::new(Digest384::ZERO);
    let mut levels = Vec::with_capacity(STATE_TREE_DEPTH);
    for depth in 0..STATE_TREE_DEPTH {
        let path_child = usize::from(path_nibble(object_id, depth).expect("valid depth"));
        let bitmap = u16::MAX ^ (1_u16 << path_child);
        let siblings = vec![digest(0x80_u8.wrapping_add(depth as u8)); 15];
        levels.push(StateProofLevel::new(bitmap, siblings).expect("fifteen siblings"));
    }
    let proof = StateProof::new(StateProofKind::NonMembership, object_id, levels)
        .expect("maximal proof is canonical");
    assert_eq!(
        encode_body(&proof).expect("maximal proof encodes").len(),
        StateProof::MAX_ENCODED_LEN
    );
}

proptest! {
    #[test]
    fn every_key_depth_refines_the_independent_nibble_and_partition_oracle(
        bytes in any::<[u8; 48]>(),
        depth in 0_usize..STATE_TREE_DEPTH,
    ) {
        let object_id = ObjectId::new(Digest384::new(bytes));
        let byte = bytes[depth / 2];
        let expected = if depth.is_multiple_of(2) { byte >> 4 } else { byte & 0x0f };
        prop_assert_eq!(path_nibble(object_id, depth), Some(expected));
        prop_assert!(expected < STATE_TREE_ARITY as u8);
        prop_assert_eq!(
            partition_id(object_id),
            (u16::from(bytes[0]) << 4) | (u16::from(bytes[1]) >> 4)
        );
        prop_assert_eq!(path_nibble(object_id, STATE_TREE_DEPTH), None);
    }

    #[test]
    fn changing_an_object_version_changes_the_state_root(version in 0_u64..u64::MAX) {
        let object_id = object_id_with_ends(0x10, 0x10);
        let before = object(object_id, version);
        let after = object(object_id, version + 1);
        let before_root = commit_objects(&[before]).expect("state commits");
        let after_root = commit_objects(&[after]).expect("state commits");
        prop_assert_ne!(before_root, after_root);
    }


    #[test]
    fn authenticated_replacement_refines_full_recomputation(
        before_version in any::<u64>(),
        after_version in any::<u64>(),
    ) {
        let object_id = object_id_with_ends(0x10, 0x10);
        let before = object(object_id, before_version);
        let after = object(object_id, after_version);
        let pre = commit_objects(core::slice::from_ref(&before)).expect("state commits");
        let proof = prove_object(core::slice::from_ref(&before), object_id).expect("proof");
        let incremental = apply_single_key_update(pre, &proof, Some(&before), Some(&after))
            .expect("authenticated replacement");
        let recomputed = commit_objects(core::slice::from_ref(&after)).expect("state commits");
        prop_assert_eq!(incremental, recomputed);
    }
}
