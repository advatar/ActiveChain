use activechain_application_primitives::{
    AnchorBatchProofV1, DigestAnchorStatementV1, anchor_leaf_hash, anchor_node_hash,
};
use activechain_canonical_codec::{CanonicalType, encode_envelope};
use activechain_protocol_commitment::{DomainTag, commit};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let domain = b"mademark.external-anchor.statement.v1".to_vec();
    let left = DigestAnchorStatementV1::new(domain.clone(), [0x11; 32]).unwrap();
    let right = DigestAnchorStatementV1::new(domain, [0x22; 32]).unwrap();
    let left_hash = anchor_leaf_hash(&left);
    let right_hash = anchor_leaf_hash(&right);
    let root = anchor_node_hash(left_hash, right_hash);
    let proof = AnchorBatchProofV1::new(0, 2, vec![right_hash]).unwrap();
    let envelope = encode_envelope(&left).unwrap();
    let proof_envelope = encode_envelope(&proof).unwrap();
    println!("application_domain=mademark.external-anchor.statement.v1");
    println!("digest_sha256={}", hex(left.digest()));
    println!("statement_type_tag=0x{:04x}", DigestAnchorStatementV1::TYPE_TAG);
    println!("statement_schema_version={}", DigestAnchorStatementV1::SCHEMA_VERSION);
    println!("statement_body_length={}", envelope.len() - 5);
    println!("statement_canonical_bytes_hex={}", hex(&envelope));
    println!("submission_reference={}", hex(left.submission_reference().unwrap().as_bytes()));
    println!(
        "statement_canonical_value_commitment_hex={}",
        hex(left.submission_reference().unwrap().as_bytes())
    );
    println!("batch_leaf_hash={}", hex(&left_hash));
    println!("batch_sibling_hash={}", hex(&right_hash));
    println!("batch_root={}", hex(&root));
    println!("batch_proof_type_tag=0x{:04x}", AnchorBatchProofV1::TYPE_TAG);
    println!("batch_proof_schema_version={}", AnchorBatchProofV1::SCHEMA_VERSION);
    println!("batch_proof_body_length={}", proof_envelope.len() - 5);
    println!("batch_proof_canonical_bytes_hex={}", hex(&proof_envelope));
    println!(
        "batch_proof_canonical_value_commitment_hex={}",
        hex(commit(DomainTag::CANONICAL_VALUE, &proof).unwrap().as_bytes())
    );
    assert!(proof.verify(&left, root));
}
