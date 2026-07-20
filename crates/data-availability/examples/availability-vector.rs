use activechain_data_availability::AvailabilityBatch;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let batch = AvailabilityBatch::encode(b"ACT-DA-V1", 4, 2).unwrap();
    println!("serialized_proof_hex={}", hex(&batch.serialize().unwrap()));
    println!("commitment_count={}", batch.commitments().len());
    println!("payload_commitment={}", hex(batch.payload_commitment().unwrap().as_bytes()));
}
