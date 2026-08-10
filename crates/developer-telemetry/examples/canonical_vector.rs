use activechain_developer_telemetry::{
    Authorization, Category, Collector, EventInput, EventMeasurementInput, EventSigner,
};
use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey, signature::SignatureEncoding};
use serde_json::json;
use std::collections::BTreeSet;

struct VectorSigner(SigningKey<MlDsa44>);
impl EventSigner for VectorSigner {
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.0.sign(payload).to_bytes().to_vec()
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().encode().as_slice().to_vec()
    }
}
fn digest(byte: u8) -> String {
    hex::encode([byte; 48])
}

fn main() {
    let signer = VectorSigner(SigningKey::from_seed(&Seed::from([7; 32])));
    let path =
        std::env::temp_dir().join(format!("actum-telemetry-vector-{}.json", std::process::id()));
    let authorization = Authorization {
        revision: 7,
        project_id: digest(2),
        policy_id: digest(3),
        purpose: "canonical vector".into(),
        categories: BTreeSet::from([Category::BuildTest]),
        valid_from_ms: 1,
        retain_until_ms: 10_000,
    };
    let mut collector = Collector::create(&path, authorization, &signer, 1).unwrap();
    for index in 1..=3_u64 {
        collector
            .record(
                EventInput {
                    measurement: EventMeasurementInput::BuildTest {
                        run_count: 1,
                        test_count: u32::try_from(index).unwrap(),
                    },
                    wall_start_ms: 100 + index,
                    wall_end_ms: 200 + index,
                    monotonic_start_ns: 1_000 + index * 20,
                    monotonic_end_ns: 1_010 + index * 20,
                    source_commitment: digest(4),
                    subject_commitment: digest(5),
                    payload_commitment: digest(index as u8 + 5),
                },
                &signer,
                1_000,
            )
            .unwrap();
    }
    let events = collector.events().to_vec();
    let epoch = collector.seal_epoch().unwrap();
    let output = json!({
        "profile": "actum.developer-telemetry.canonical.v1",
        "seed_hex": hex::encode([7_u8; 32]),
        "events": events,
        "epoch": epoch,
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    let _ = std::fs::remove_file(path);
}
