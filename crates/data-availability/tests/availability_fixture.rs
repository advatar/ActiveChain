use activechain_data_availability::AvailabilityBatch;

fn field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(name).and_then(|value| value.strip_prefix('=')))
        .unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn checked_in_fixture_is_verified_by_the_da_kernel() {
    let fixture = include_str!("../../../testing/vectors/availability/availability-v1.txt");
    let proof = decode_hex(field(fixture, "serialized_proof_hex"));
    let batch = AvailabilityBatch::deserialize(&proof).unwrap();
    let expected = decode_hex(field(fixture, "payload_commitment"));
    assert_eq!(batch.payload_commitment().unwrap().as_bytes(), expected.as_slice());
    assert_eq!(batch.reconstruct_payload(&[]).unwrap(), b"ACT-DA-V1");
}
