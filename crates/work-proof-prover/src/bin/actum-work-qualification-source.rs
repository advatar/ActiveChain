//! Creates one privacy-bounded, genuinely signed collector epoch for the
//! private Kanalen end-to-end qualification.
//!
//! The collector key is generated in memory and never persisted. The output
//! contains only canonical signed commitments and the sealed public epoch.

use activechain_canonical_codec::encode_envelope;
use activechain_developer_telemetry::{
    Authorization, Category, Collector, EventInput, EventMeasurementInput, EventSigner,
};
use activechain_work_proof::MeteringPolicyV1;
use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey, signature::SignatureEncoding};
use serde_json::json;
use std::{
    collections::BTreeSet,
    env, fs,
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

struct EphemeralSigner(SigningKey<MlDsa44>);

impl EventSigner for EphemeralSigner {
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.0.sign(payload).to_bytes().to_vec()
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().encode().as_slice().to_vec()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let policy = qualification_policy();
    let policy_id =
        policy.policy_id().map_err(|_| "qualification policy could not be committed")?;
    if arguments == ["--policy-id"] {
        println!("{}", hex(policy_id.as_bytes()));
        return Ok(());
    }
    let [source_output, policy_output, project_id, now_ms] = arguments.as_slice() else {
        return Err("usage: actum-work-qualification-source <source-out> <policy-hex-out> \
             <project-id-hex> <now-ms>\n       actum-work-qualification-source --policy-id"
            .into());
    };
    let now_ms = now_ms.parse::<u64>()?;
    if now_ms < 1_000 {
        return Err("now-ms is too small for a bounded qualification event".into());
    }
    let source_output = Path::new(source_output);
    let policy_output = Path::new(policy_output);
    if source_output.exists() || policy_output.exists() {
        return Err("refusing to overwrite qualification output".into());
    }

    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed)?;
    let signer = EphemeralSigner(SigningKey::from_seed(&Seed::from(seed)));
    seed.zeroize();

    let collector_path = temporary_collector_path(source_output)?;
    let _cleanup = CollectorStateCleanup(collector_path.clone());
    let authorization = Authorization {
        revision: policy.revision,
        project_id: project_id.clone(),
        policy_id: hex(policy_id.as_bytes()),
        purpose: "Kanalen private-testnet end-to-end qualification".to_owned(),
        categories: BTreeSet::from([Category::GitArtifact]),
        valid_from_ms: now_ms - 1_000,
        retain_until_ms: now_ms.saturating_add(86_400_000),
    };
    let mut collector = Collector::create(&collector_path, authorization, &signer, now_ms)
        .map_err(|_| "qualification collector could not be created")?;
    collector
        .record(
            EventInput {
                measurement: EventMeasurementInput::GitArtifact { artifact_count: 1 },
                wall_start_ms: now_ms - 500,
                wall_end_ms: now_ms,
                monotonic_start_ns: 1_000_000,
                monotonic_end_ns: 2_000_000,
                source_commitment: random_digest()?,
                subject_commitment: random_digest()?,
                payload_commitment: random_digest()?,
            },
            &signer,
            now_ms,
        )
        .map_err(|_| "qualification event could not be recorded")?;
    let events = collector.events().to_vec();
    let epoch = collector.seal_epoch().map_err(|_| "qualification epoch could not be sealed")?;
    let source = json!({
        "schema": "actum.work-claim.source.v1",
        "class": "contribution",
        "epoch": epoch,
        "events": events,
    });
    write_private(source_output, &serde_json::to_vec(&source)?)?;
    let policy_envelope =
        encode_envelope(&policy).map_err(|_| "qualification policy could not be encoded")?;
    write_private(policy_output, format!("{}\n", hex(&policy_envelope)).as_bytes())?;
    println!("project_id {project_id}");
    println!("policy_id {}", hex(policy_id.as_bytes()));
    println!("source {}", source_output.display());
    Ok(())
}

fn qualification_policy() -> MeteringPolicyV1 {
    MeteringPolicyV1 {
        revision: 1,
        accepted_measurement_kinds: 0x1f,
        idle_timeout_ms: 300_000,
        max_human_event_ms: 300_000,
        max_attention_claim_ms: 28_800_000,
        model_input_weight: 500_000,
        model_output_weight: 2_000_000,
    }
}

fn random_digest() -> Result<String, getrandom::Error> {
    let mut bytes = [0_u8; 48];
    getrandom::fill(&mut bytes)?;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[47] = 1;
    }
    Ok(hex(&bytes))
}

fn temporary_collector_path(output: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let parent = output.parent().ok_or("source output has no parent directory")?;
    let name = output.file_name().ok_or("source output has no file name")?.to_string_lossy();
    Ok(parent.join(format!(".{name}.collector.{}", std::process::id())))
}

struct CollectorStateCleanup(PathBuf);

impl Drop for CollectorStateCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualification_policy_identity_is_stable() {
        assert_eq!(
            hex(qualification_policy().policy_id().unwrap().as_bytes()),
            "01456c3f54e61fb20466c111f4167916b1ee9d23ac083a0e3ce1662b153c47de27af0a13b09cb5319c24ba31a9cfa8d0"
        );
    }
}
