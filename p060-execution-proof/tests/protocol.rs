use std::panic::{AssertUnwindSafe, catch_unwind};

use p060::{Action, Block, ExpectedContext, Receipt, VerifyError, prove, verify_receipt};

fn sample() -> (Block, Vec<u8>) {
    let block = Block::new(vec![Action::add(7), Action::mul(9), Action::add(11)]).unwrap();
    let bytes = prove(5, &block).unwrap().encode().unwrap();
    (block, bytes)
}

#[test]
fn positive_proof_is_deterministic_and_verifies() {
    let (block, first) = sample();
    let second = prove(5, &block).unwrap().encode().unwrap();
    assert_eq!(
        first, second,
        "pinned single-threaded prover must be byte-reproducible"
    );

    let expected = ExpectedContext::active(5, &block, 119).unwrap();
    let report = verify_receipt(&first, Some(&expected)).unwrap();
    assert_eq!(119, report.post_state);
    assert!(report.conjectured_soundness_bits >= 100);
}

#[test]
fn registered_header_and_every_public_binding_are_enforced() {
    let (_, bytes) = sample();

    let mut wrong_kind = bytes.clone();
    wrong_kind[11] ^= 1;
    assert!(matches!(
        verify_receipt(&wrong_kind, None),
        Err(VerifyError::ReceiptKind(_))
    ));

    let mut wrong_protocol = bytes.clone();
    wrong_protocol[15] ^= 1;
    assert!(matches!(
        verify_receipt(&wrong_protocol, None),
        Err(VerifyError::ProtocolVersion(_))
    ));

    let mut wrong_verifier = bytes.clone();
    wrong_verifier[19] ^= 1;
    assert!(matches!(
        verify_receipt(&wrong_verifier, None),
        Err(VerifyError::VerifierVersion(_))
    ));

    let mut wrong_suite = bytes.clone();
    wrong_suite[23] ^= 1;
    assert!(matches!(
        verify_receipt(&wrong_suite, None),
        Err(VerifyError::Suite(_))
    ));

    let mut wrong_program = bytes.clone();
    wrong_program[28] ^= 1;
    assert!(matches!(
        verify_receipt(&wrong_program, None),
        Err(VerifyError::ProgramIdentity)
    ));

    let mut wrong_pre_root = bytes.clone();
    wrong_pre_root[76] ^= 1;
    assert!(verify_receipt(&wrong_pre_root, None).is_err());

    let mut wrong_block_id = bytes.clone();
    wrong_block_id[124] ^= 1;
    assert!(verify_receipt(&wrong_block_id, None).is_err());

    let mut wrong_post_root = bytes.clone();
    wrong_post_root[172] ^= 1;
    assert!(verify_receipt(&wrong_post_root, None).is_err());

    // Public-input envelope begins at 228; the pre-state begins after its 12-byte prefix.
    let mut changed_public_pre_state = bytes.clone();
    changed_public_pre_state[247] ^= 1;
    assert!(verify_receipt(&changed_public_pre_state, None).is_err());

    // Public block begins at 260 and its first opcode begins after its 16-byte header.
    let mut changed_block = bytes.clone();
    changed_block[276] ^= 1;
    assert!(verify_receipt(&changed_block, None).is_err());

    let public_len = u32::from_be_bytes(bytes[220..224].try_into().unwrap()) as usize;
    let proof_start = 228 + public_len;
    let mut changed_proof = bytes.clone();
    changed_proof[proof_start + 32] ^= 1;
    assert!(verify_receipt(&changed_proof, None).is_err());
}

#[test]
fn strict_lengths_trailing_bytes_and_expected_context_are_enforced() {
    let (block, bytes) = sample();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify_receipt(&trailing, None).is_err());

    let mut wrong_expected = ExpectedContext::active(5, &block, 119).unwrap();
    wrong_expected.post_state_root[0] ^= 1;
    assert!(matches!(
        verify_receipt(&bytes, Some(&wrong_expected)),
        Err(VerifyError::ContextMismatch("post-state root"))
    ));
}

#[test]
fn arbitrary_and_malformed_inputs_never_escape_as_panics() {
    let mut seed = 0x5eed_f00d_dead_beef_u64;
    for len in 0..512 {
        let mut bytes = vec![0_u8; len];
        for byte in &mut bytes {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = seed as u8;
        }
        assert!(catch_unwind(AssertUnwindSafe(|| verify_receipt(&bytes, None))).is_ok());
    }

    let block = Block::new(vec![Action::add(1)]).unwrap();
    for proof_len in 1..64 {
        let post = block.execute(4).unwrap();
        let header = p060::ReceiptHeader::for_execution(4, post, &block).unwrap();
        let receipt = Receipt::new(header, 4, post, block.clone(), vec![0xa5; proof_len]).unwrap();
        let bytes = receipt.encode().unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| verify_receipt(&bytes, None))).is_ok());
    }
}
