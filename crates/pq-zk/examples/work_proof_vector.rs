use activechain_canonical_codec::decode_envelope;
use activechain_pq_zk::execute_work_non_overlap_relation;
use activechain_work_proof::WorkClaimRelationInputV1;

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid hex"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
fn main() {
    let vector = std::fs::read_to_string("testing/vectors/application/work-claim-v1.txt").unwrap();
    let envelope = vector.lines().find_map(|line| line.strip_prefix("relation_envelope=")).unwrap();
    let input: WorkClaimRelationInputV1 = decode_envelope(&decode_hex(envelope)).unwrap();
    let journal = execute_work_non_overlap_relation(&input).unwrap();
    println!("profile=actum.non-overlap.risc0.v1");
    println!("proof_system_revision={}", activechain_pq_zk::WORK_PROOF_SYSTEM_REVISION);
    println!("receipt_envelope_type_tag=0x01bd");
    println!(
        "image_id_u32_le={}",
        activechain_pq_zk_methods::WORK_NON_OVERLAP_ID
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("journal={}", hex(&journal));
}
