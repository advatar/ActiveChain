#![forbid(unsafe_code)]

//! ActiveChain-owned boundary for authenticated collector output, canonical claim assembly,
//! private proving, and verifier/anchor artifact construction.

use activechain_application_primitives::{ActivityEpochV1, TelemetryEpochAnchorRequestV1};
use activechain_canonical_codec::{CanonicalType, decode_envelope, encode_envelope};
use activechain_developer_telemetry::{
    SealedActivityEpochV1, SignedDeveloperEventV1, verify_event,
};
use activechain_protocol_types::Digest384;
use activechain_work_proof::{
    MeteringPolicyV1, WorkClaimClassV1, WorkClaimRelationInputV1, build_work_claim_relation,
    derive_work_claim_id,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_384};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroize;

pub const SOURCE_SCHEMA_V1: &str = "actum.work-claim.source.v1";
pub const CONFIG_SCHEMA_V1: &str = "actum.work-prover.config.v1";
pub const ADMISSION_SCHEMA_V1: &str = "actum.work-proof.admit.request.v1";
pub const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_ADMISSION_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SIDECAR_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_SIDECAR_REQUEST_BYTES: usize = 8 * 1024;
const REQUEST_SOURCE_FILE: &str = "source.sha3-384";
const REQUEST_ARTIFACT_FILE: &str = "admission.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceClaimClassV1 {
    Attention,
    Compute,
    Contribution,
}

impl From<SourceClaimClassV1> for WorkClaimClassV1 {
    fn from(value: SourceClaimClassV1) -> Self {
        match value {
            SourceClaimClassV1::Attention => Self::Attention,
            SourceClaimClassV1::Compute => Self::Compute,
            SourceClaimClassV1::Contribution => Self::Contribution,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkClaimSourceV1 {
    pub schema: String,
    pub class: SourceClaimClassV1,
    pub epoch: SealedActivityEpochV1,
    pub events: Vec<SignedDeveloperEventV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkProverConfigV1 {
    pub schema: String,
    pub chain_id: String,
    pub genesis_commitment: String,
    pub usage_domain: String,
    pub submitter_id: String,
    pub policy_envelope_hex: String,
    pub claimant_secret_file: PathBuf,
    pub output_directory: PathBuf,
    pub socket_path: PathBuf,
    pub r0vm_path: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionArtifactV1 {
    pub schema: String,
    pub operation: String,
    pub profile: String,
    pub claim_id: String,
    pub public_claim_envelope_hex: String,
    pub proof_envelope_hex: String,
    pub anchor_request_envelope_hex: String,
    pub checkpointed_anchor_evidence_envelope_hex: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProverCliResponseV1 {
    pub status: &'static str,
    pub artifact_path: String,
    pub anchor_request_id: String,
    pub project_id: String,
    pub claim_id: String,
}

#[derive(Debug)]
pub enum ProverError {
    Invalid,
    Conflict,
    Unavailable,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SidecarRequestV1 {
    input_path: PathBuf,
    request_id: String,
}

pub struct PreparedClaimV1 {
    pub relation: WorkClaimRelationInputV1,
    pub anchor_request: TelemetryEpochAnchorRequestV1,
}

pub fn prepare_claim(
    config: &WorkProverConfigV1,
    source: &WorkClaimSourceV1,
    claimant_secret: Digest384,
    request_id: &[u8],
) -> Result<PreparedClaimV1, ProverError> {
    validate_request_id(request_id)?;
    if config.schema != CONFIG_SCHEMA_V1 || source.schema != SOURCE_SCHEMA_V1 {
        return Err(ProverError::Invalid);
    }
    let chain_id = decode_digest(&config.chain_id)?;
    let genesis = decode_digest(&config.genesis_commitment)?;
    let usage_domain = decode_digest(&config.usage_domain)?;
    let submitter_id = decode_digest(&config.submitter_id)?;
    let policy_bytes =
        decode_lower_hex(&config.policy_envelope_hex, MeteringPolicyV1::MAX_ENCODED_LEN + 9)?;
    let policy: MeteringPolicyV1 =
        decode_envelope(&policy_bytes).map_err(|_| ProverError::Invalid)?;
    let epoch: ActivityEpochV1 = source.epoch.epoch().map_err(|_| ProverError::Invalid)?;
    if decode_digest(&source.epoch.epoch_id)?
        != epoch.epoch_id().map_err(|_| ProverError::Invalid)?
    {
        return Err(ProverError::Invalid);
    }
    if source.events.is_empty()
        || source.events.len()
            != usize::try_from(epoch.event_count).map_err(|_| ProverError::Invalid)?
    {
        return Err(ProverError::Invalid);
    }
    let events = source
        .events
        .iter()
        .map(|signed| {
            verify_event(signed).map_err(|_| ProverError::Invalid)?;
            signed.event().map_err(|_| ProverError::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let relation = build_work_claim_relation(
        chain_id,
        genesis,
        usage_domain,
        claimant_secret,
        &epoch,
        &events,
        policy,
        source.class.into(),
    )
    .map_err(|_| ProverError::Invalid)?;
    let anchor_request = TelemetryEpochAnchorRequestV1::new(
        chain_id,
        genesis,
        1,
        submitter_id,
        request_id.to_vec(),
        epoch,
    )
    .map_err(|_| ProverError::Invalid)?;
    Ok(PreparedClaimV1 { relation, anchor_request })
}

pub fn prove_from_files(
    config_path: &Path,
    input_path: &Path,
    request_id: &str,
) -> Result<ProverCliResponseV1, ProverError> {
    validate_request_id(request_id.as_bytes())?;
    let config_bytes = read_private_file(config_path, 64 * 1024)?;
    let config: WorkProverConfigV1 =
        serde_json::from_slice(&config_bytes).map_err(|_| ProverError::Invalid)?;
    if config.schema != CONFIG_SCHEMA_V1 {
        return Err(ProverError::Invalid);
    }
    if !config.claimant_secret_file.is_absolute()
        || !config.output_directory.is_absolute()
        || !config.socket_path.is_absolute()
        || !config.r0vm_path.is_absolute()
    {
        return Err(ProverError::Invalid);
    }
    ensure_private_directory(&config.output_directory)?;
    let lock_path = config.output_directory.join("prover.lock");
    reject_non_file_if_present(&lock_path)?;
    let lock = private_file_options(false).open(lock_path).map_err(|_| ProverError::Unavailable)?;
    lock.try_lock().map_err(|_| ProverError::Unavailable)?;

    let source_bytes = read_private_file(input_path, MAX_SOURCE_BYTES)?;
    let source_commitment = source_commitment(&source_bytes);
    let request_directory = config.output_directory.join(request_id);
    if request_directory.exists() {
        return recover_existing(&request_directory, source_commitment, request_id);
    }
    let source: WorkClaimSourceV1 =
        serde_json::from_slice(&source_bytes).map_err(|_| ProverError::Invalid)?;
    let mut secret_bytes = read_private_file(&config.claimant_secret_file, 256)?;
    let claimant_secret = {
        let secret_text = std::str::from_utf8(&secret_bytes).map_err(|_| ProverError::Invalid)?;
        decode_digest(secret_text.trim_end())?
    };
    secret_bytes.zeroize();
    let mut prepared = prepare_claim(&config, &source, claimant_secret, request_id.as_bytes())?;
    let proof =
        activechain_pq_zk::prove_work_non_overlap_external(&prepared.relation, &config.r0vm_path)
            .map_err(|_| ProverError::Unavailable)?;
    prepared.relation.claimant_secret = Digest384::ZERO;
    let proof_envelope = proof.to_envelope_bytes().map_err(|_| ProverError::Unavailable)?;
    let claim_id = derive_work_claim_id(&prepared.relation.public, &proof_envelope)
        .map_err(|_| ProverError::Invalid)?;
    let artifact = AdmissionArtifactV1 {
        schema: ADMISSION_SCHEMA_V1.to_owned(),
        operation: "verify_and_register".to_owned(),
        profile: activechain_work_proof::PROFILE.to_owned(),
        claim_id: digest_hex(claim_id),
        public_claim_envelope_hex: lower_hex(
            &encode_envelope(&prepared.relation.public).map_err(|_| ProverError::Invalid)?,
        ),
        proof_envelope_hex: lower_hex(&proof_envelope),
        anchor_request_envelope_hex: lower_hex(
            &encode_envelope(&prepared.anchor_request).map_err(|_| ProverError::Invalid)?,
        ),
        checkpointed_anchor_evidence_envelope_hex: None,
    };
    let artifact_bytes = serde_json::to_vec(&artifact).map_err(|_| ProverError::Unavailable)?;
    if artifact_bytes.len() > MAX_ADMISSION_BYTES {
        return Err(ProverError::Unavailable);
    }
    persist_request_directory(
        &config.output_directory,
        &request_directory,
        source_commitment,
        &artifact_bytes,
    )?;
    Ok(response(
        &request_directory,
        request_id,
        digest_hex(prepared.relation.public.project_id),
        artifact.claim_id,
    ))
}

#[cfg(unix)]
pub fn serve_sidecar(config_path: &Path) -> Result<(), ProverError> {
    use std::os::unix::{fs::FileTypeExt, net::UnixListener};

    if !config_path.is_absolute() {
        return Err(ProverError::Invalid);
    }
    let config_bytes = read_private_file(config_path, 64 * 1024)?;
    let config: WorkProverConfigV1 =
        serde_json::from_slice(&config_bytes).map_err(|_| ProverError::Invalid)?;
    if config.schema != CONFIG_SCHEMA_V1 || !config.socket_path.is_absolute() {
        return Err(ProverError::Invalid);
    }
    let socket_parent = config.socket_path.parent().ok_or(ProverError::Invalid)?;
    require_private_directory(socket_parent)?;
    let lock_path = config.socket_path.with_extension("lock");
    reject_non_file_if_present(&lock_path)?;
    let lock = private_file_options(false).open(lock_path).map_err(|_| ProverError::Unavailable)?;
    lock.try_lock().map_err(|_| ProverError::Unavailable)?;
    match fs::symlink_metadata(&config.socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(&config.socket_path).map_err(|_| ProverError::Unavailable)?;
        }
        Ok(_) => return Err(ProverError::Invalid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ProverError::Unavailable),
    }
    let listener = UnixListener::bind(&config.socket_path).map_err(|_| ProverError::Unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600))
            .map_err(|_| ProverError::Unavailable)?;
    }
    let _socket = SocketCleanup(config.socket_path.clone());
    for connection in listener.incoming() {
        let Ok(mut stream) = connection else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let response = match read_sidecar_request(&mut stream).and_then(|request| {
            prove_from_files(config_path, &request.input_path, &request.request_id)
        }) {
            Ok(response) => serde_json::to_vec(&response).map_err(|_| ProverError::Unavailable),
            Err(ProverError::Invalid | ProverError::Conflict) => {
                Ok(br#"{"status":"invalid"}"#.to_vec())
            }
            Err(ProverError::Unavailable) => Ok(br#"{"status":"unavailable"}"#.to_vec()),
        };
        if let Ok(response) = response {
            let _ = stream.write_all(&response);
            let _ = stream.write_all(b"\n");
        }
    }
    drop(lock);
    Ok(())
}

#[cfg(not(unix))]
pub fn serve_sidecar(_: &Path) -> Result<(), ProverError> {
    Err(ProverError::Unavailable)
}

#[cfg(unix)]
pub fn request_proof_over_socket(
    socket_path: &Path,
    input_path: &Path,
    request_id: &str,
) -> Result<Vec<u8>, ProverError> {
    use std::net::Shutdown;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixStream;

    validate_request_id(request_id.as_bytes())?;
    if !socket_path.is_absolute() || !input_path.is_absolute() {
        return Err(ProverError::Invalid);
    }
    let metadata = fs::symlink_metadata(socket_path).map_err(|_| ProverError::Unavailable)?;
    if !metadata.file_type().is_socket() {
        return Err(ProverError::Invalid);
    }
    require_private_mode(&metadata)?;
    let request = SidecarRequestV1 {
        input_path: input_path.to_path_buf(),
        request_id: request_id.to_owned(),
    };
    let encoded = serde_json::to_vec(&request).map_err(|_| ProverError::Invalid)?;
    if encoded.len() > MAX_SIDECAR_REQUEST_BYTES {
        return Err(ProverError::Invalid);
    }
    let mut stream = UnixStream::connect(socket_path).map_err(|_| ProverError::Unavailable)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(900)))
        .map_err(|_| ProverError::Unavailable)?;
    stream.write_all(&encoded).map_err(|_| ProverError::Unavailable)?;
    stream.write_all(b"\n").map_err(|_| ProverError::Unavailable)?;
    stream.shutdown(Shutdown::Write).map_err(|_| ProverError::Unavailable)?;
    let mut response = Vec::new();
    stream
        .take(u64::try_from(MAX_SIDECAR_RESPONSE_BYTES + 1).map_err(|_| ProverError::Unavailable)?)
        .read_to_end(&mut response)
        .map_err(|_| ProverError::Unavailable)?;
    if response.is_empty() || response.len() > MAX_SIDECAR_RESPONSE_BYTES {
        return Err(ProverError::Unavailable);
    }
    while response.last().is_some_and(u8::is_ascii_whitespace) {
        response.pop();
    }
    let value: serde_json::Value =
        serde_json::from_slice(&response).map_err(|_| ProverError::Unavailable)?;
    if !value.is_object() {
        return Err(ProverError::Unavailable);
    }
    Ok(response)
}

#[cfg(not(unix))]
pub fn request_proof_over_socket(_: &Path, _: &Path, _: &str) -> Result<Vec<u8>, ProverError> {
    Err(ProverError::Unavailable)
}

fn read_sidecar_request(reader: &mut impl Read) -> Result<SidecarRequestV1, ProverError> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(MAX_SIDECAR_REQUEST_BYTES + 1).map_err(|_| ProverError::Invalid)?)
        .read_to_end(&mut bytes)
        .map_err(|_| ProverError::Unavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_SIDECAR_REQUEST_BYTES {
        return Err(ProverError::Invalid);
    }
    let request: SidecarRequestV1 =
        serde_json::from_slice(&bytes).map_err(|_| ProverError::Invalid)?;
    validate_request_id(request.request_id.as_bytes())?;
    if !request.input_path.is_absolute() {
        return Err(ProverError::Invalid);
    }
    Ok(request)
}

struct SocketCleanup(PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn recover_existing(
    request_directory: &Path,
    expected_source: Digest384,
    request_id: &str,
) -> Result<ProverCliResponseV1, ProverError> {
    require_private_directory(request_directory)?;
    let source_bytes = read_private_file(&request_directory.join(REQUEST_SOURCE_FILE), 128)?;
    let source = std::str::from_utf8(&source_bytes).map_err(|_| ProverError::Invalid)?;
    if source.trim_end() != digest_hex(expected_source) {
        return Err(ProverError::Conflict);
    }
    let artifact_path = request_directory.join(REQUEST_ARTIFACT_FILE);
    let bytes = read_private_file(&artifact_path, MAX_ADMISSION_BYTES as u64)?;
    let artifact: AdmissionArtifactV1 =
        serde_json::from_slice(&bytes).map_err(|_| ProverError::Invalid)?;
    if artifact.schema != ADMISSION_SCHEMA_V1
        || artifact.operation != "verify_and_register"
        || artifact.profile != activechain_work_proof::PROFILE
        || artifact.checkpointed_anchor_evidence_envelope_hex.is_some()
    {
        return Err(ProverError::Invalid);
    }
    let public_bytes = decode_lower_hex(
        &artifact.public_claim_envelope_hex,
        activechain_work_proof::WorkClaimPublicV1::MAX_ENCODED_LEN + 9,
    )?;
    let public: activechain_work_proof::WorkClaimPublicV1 =
        decode_envelope(&public_bytes).map_err(|_| ProverError::Invalid)?;
    let proof =
        decode_lower_hex(&artifact.proof_envelope_hex, activechain_pq_zk::MAX_WORK_PROOF_BYTES)?;
    activechain_pq_zk::WorkNonOverlapProof::from_envelope_bytes(&proof, &public)
        .map_err(|_| ProverError::Invalid)?;
    let claim_id = decode_digest(&artifact.claim_id)?;
    if derive_work_claim_id(&public, &proof).map_err(|_| ProverError::Invalid)? != claim_id {
        return Err(ProverError::Invalid);
    }
    let anchor_bytes = decode_lower_hex(
        &artifact.anchor_request_envelope_hex,
        TelemetryEpochAnchorRequestV1::MAX_ENCODED_LEN + 9,
    )?;
    let anchor: TelemetryEpochAnchorRequestV1 =
        decode_envelope(&anchor_bytes).map_err(|_| ProverError::Invalid)?;
    if anchor.client_request_id != request_id.as_bytes()
        || anchor.chain_id != public.chain_id
        || anchor.genesis_commitment != public.genesis
        || anchor.telemetry_schema_revision != public.telemetry_schema
        || anchor.epoch.collector_id != public.collector_id
        || anchor.epoch.project_id != public.project_id
        || anchor.epoch.event_root != public.epoch_root
        || anchor.epoch.event_count != public.epoch_event_count
        || anchor.epoch.authorization_revision != public.authorization_revision
        || anchor.epoch.policy_id != public.policy_id
    {
        return Err(ProverError::Invalid);
    }
    Ok(response(request_directory, request_id, digest_hex(public.project_id), artifact.claim_id))
}

fn response(
    request_directory: &Path,
    request_id: &str,
    project_id: String,
    claim_id: String,
) -> ProverCliResponseV1 {
    ProverCliResponseV1 {
        status: "proof_generated",
        artifact_path: request_directory.join(REQUEST_ARTIFACT_FILE).display().to_string(),
        anchor_request_id: request_id.to_owned(),
        project_id,
        claim_id,
    }
}

fn persist_request_directory(
    output: &Path,
    destination: &Path,
    source: Digest384,
    artifact: &[u8],
) -> Result<(), ProverError> {
    let mut temporary = None;
    for attempt in 0..16_u8 {
        let candidate = output.join(format!(".request.{}.{}.tmp", std::process::id(), attempt));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                set_private_directory_mode(&candidate)?;
                temporary = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(ProverError::Unavailable),
        }
    }
    let temporary = temporary.ok_or(ProverError::Unavailable)?;
    let result = (|| {
        write_private_file(
            &temporary.join(REQUEST_SOURCE_FILE),
            format!("{}\n", digest_hex(source)).as_bytes(),
        )?;
        write_private_file(&temporary.join(REQUEST_ARTIFACT_FILE), artifact)?;
        File::open(&temporary)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ProverError::Unavailable)?;
        fs::rename(&temporary, destination).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ProverError::Conflict
            } else {
                ProverError::Unavailable
            }
        })?;
        File::open(output)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ProverError::Unavailable)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn source_commitment(bytes: &[u8]) -> Digest384 {
    let mut hash = Sha3_384::new();
    hash.update(b"ACTUM-WORK-PROVER-SOURCE-V1");
    hash.update(bytes);
    Digest384::new(hash.finalize().into())
}

fn validate_request_id(value: &[u8]) -> Result<(), ProverError> {
    if value.is_empty()
        || value.len() > 128
        || value.iter().any(|byte| {
            !matches!(*byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'-')
        })
    {
        return Err(ProverError::Invalid);
    }
    Ok(())
}

fn decode_digest(value: &str) -> Result<Digest384, ProverError> {
    let bytes = decode_lower_hex(value, 48)?;
    let bytes: [u8; 48] = bytes.try_into().map_err(|_| ProverError::Invalid)?;
    let value = Digest384::new(bytes);
    if value == Digest384::ZERO {
        return Err(ProverError::Invalid);
    }
    Ok(value)
}

fn decode_lower_hex(value: &str, maximum: usize) -> Result<Vec<u8>, ProverError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > maximum.saturating_mul(2)
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProverError::Invalid);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            Ok((nibble(pair[0]).ok_or(ProverError::Invalid)? << 4)
                | nibble(pair[1]).ok_or(ProverError::Invalid)?)
        })
        .collect()
}

const fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn digest_hex(value: Digest384) -> String {
    lower_hex(value.as_bytes())
}

fn read_private_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ProverError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProverError::Unavailable)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(ProverError::Invalid);
    }
    require_private_mode(&metadata)?;
    fs::read(path).map_err(|_| ProverError::Unavailable)
}

fn ensure_private_directory(path: &Path) -> Result<(), ProverError> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|_| ProverError::Unavailable)?;
        set_private_directory_mode(path)?;
    }
    require_private_directory(path)
}

fn require_private_directory(path: &Path) -> Result<(), ProverError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProverError::Unavailable)?;
    if !metadata.file_type().is_dir() {
        return Err(ProverError::Invalid);
    }
    require_private_mode(&metadata)
}

fn set_private_directory_mode(path: &Path) -> Result<(), ProverError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| ProverError::Unavailable)?;
    }
    Ok(())
}

fn require_private_mode(metadata: &fs::Metadata) -> Result<(), ProverError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ProverError::Invalid);
        }
    }
    Ok(())
}

fn reject_non_file_if_present(path: &Path) -> Result<(), ProverError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => require_private_mode(&metadata),
        Ok(_) => Err(ProverError::Invalid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ProverError::Unavailable),
    }
}

fn private_file_options(create_new: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ProverError> {
    let mut file = private_file_options(true).open(path).map_err(|_| ProverError::Unavailable)?;
    file.write_all(bytes).map_err(|_| ProverError::Unavailable)?;
    file.sync_all().map_err(|_| ProverError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_developer_telemetry::{
        Authorization, Category, Collector, EventInput, EventMeasurementInput, EventSigner,
    };
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey, signature::SignatureEncoding};
    use std::collections::BTreeSet;

    struct TestSigner(SigningKey<MlDsa44>);

    impl EventSigner for TestSigner {
        fn sign(&self, payload: &[u8]) -> Vec<u8> {
            self.0.sign(payload).to_bytes().to_vec()
        }

        fn public_key(&self) -> Vec<u8> {
            self.0.verifying_key().encode().as_slice().to_vec()
        }
    }

    fn digest(byte: u8) -> String {
        lower_hex(&[byte; 48])
    }

    fn fixture(directory: &Path) -> (WorkProverConfigV1, WorkClaimSourceV1) {
        let signer = TestSigner(SigningKey::from_seed(&Seed::from([7; 32])));
        let policy = MeteringPolicyV1 {
            revision: 7,
            accepted_measurement_kinds: 0x1f,
            idle_timeout_ms: 100,
            max_human_event_ms: 80,
            max_attention_claim_ms: 1_000,
            model_input_weight: 500_000,
            model_output_weight: 2_000_000,
        };
        let authorization = Authorization {
            revision: 7,
            project_id: digest(4),
            policy_id: digest_hex(policy.policy_id().unwrap()),
            purpose: "sidecar proof".to_owned(),
            categories: BTreeSet::from([Category::HumanInteraction]),
            valid_from_ms: 1,
            retain_until_ms: 10_000,
        };
        let mut collector =
            Collector::create(directory.join("collector.json"), authorization, &signer, 1).unwrap();
        collector
            .record(
                EventInput {
                    measurement: EventMeasurementInput::HumanInteraction { interaction_count: 1 },
                    wall_start_ms: 100,
                    wall_end_ms: 200,
                    monotonic_start_ns: 1_000_000,
                    monotonic_end_ns: 51_000_000,
                    source_commitment: digest(20),
                    subject_commitment: digest(21),
                    payload_commitment: digest(22),
                },
                &signer,
                1_000,
            )
            .unwrap();
        let events = collector.events().to_vec();
        let epoch = collector.seal_epoch().unwrap();
        let source = WorkClaimSourceV1 {
            schema: SOURCE_SCHEMA_V1.to_owned(),
            class: SourceClaimClassV1::Attention,
            epoch,
            events,
        };
        let config = WorkProverConfigV1 {
            schema: CONFIG_SCHEMA_V1.to_owned(),
            chain_id: digest(1),
            genesis_commitment: digest(2),
            usage_domain: digest(3),
            submitter_id: digest(5),
            policy_envelope_hex: lower_hex(&encode_envelope(&policy).unwrap()),
            claimant_secret_file: directory.join("secret"),
            output_directory: directory.join("output"),
            socket_path: directory.join("prover.sock"),
            r0vm_path: PathBuf::from("/usr/bin/false"),
        };
        (config, source)
    }

    #[test]
    fn signed_epoch_is_the_only_claim_assembly_input() {
        let directory = tempfile::tempdir().unwrap();
        let (config, source) = fixture(directory.path());
        let prepared =
            prepare_claim(&config, &source, Digest384::new([9; 48]), b"prove-1").unwrap();
        assert_eq!(prepared.relation.public.project_id, Digest384::new([4; 48]));
        assert_eq!(prepared.relation.events.len(), 1);
        assert_eq!(prepared.anchor_request.client_request_id, b"prove-1");

        let mut substituted = source;
        substituted.events[0].signature_hex.replace_range(0..2, "00");
        assert!(matches!(
            prepare_claim(&config, &substituted, Digest384::new([9; 48]), b"prove-2"),
            Err(ProverError::Invalid)
        ));
    }

    #[test]
    #[ignore = "generates and verifies a real pinned RISC Zero succinct receipt"]
    fn real_signed_source_proves_and_recovers_idempotently() {
        let directory = tempfile::tempdir().unwrap();
        let (mut config, source) = fixture(directory.path());
        config.r0vm_path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("r0vm"))
            .find(|path| path.is_file())
            .expect("r0vm must be installed for the explicit proving gate");
        let config_path = directory.path().join("config.json");
        let source_path = directory.path().join("source.json");
        write_private_file(&config_path, &serde_json::to_vec(&config).unwrap()).unwrap();
        write_private_file(&source_path, &serde_json::to_vec(&source).unwrap()).unwrap();
        write_private_file(&config.claimant_secret_file, format!("{}\n", digest(9)).as_bytes())
            .unwrap();

        let first = prove_from_files(&config_path, &source_path, "real-proof-1").unwrap();
        let retry = prove_from_files(&config_path, &source_path, "real-proof-1").unwrap();
        assert_eq!(first, retry);
        let artifact: AdmissionArtifactV1 =
            serde_json::from_slice(&fs::read(&first.artifact_path).unwrap()).unwrap();
        let public: activechain_work_proof::WorkClaimPublicV1 = decode_envelope(
            &decode_lower_hex(
                &artifact.public_claim_envelope_hex,
                activechain_work_proof::WorkClaimPublicV1::MAX_ENCODED_LEN + 9,
            )
            .unwrap(),
        )
        .unwrap();
        let proof =
            decode_lower_hex(&artifact.proof_envelope_hex, activechain_pq_zk::MAX_WORK_PROOF_BYTES)
                .unwrap();
        activechain_pq_zk::WorkNonOverlapProof::from_envelope_bytes(&proof, &public).unwrap();
        assert_eq!(artifact.claim_id, digest_hex(derive_work_claim_id(&public, &proof).unwrap()));

        let mut changed = serde_json::to_vec(&source).unwrap();
        changed.push(b' ');
        fs::write(&source_path, changed).unwrap();
        assert!(matches!(
            prove_from_files(&config_path, &source_path, "real-proof-1"),
            Err(ProverError::Conflict)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn private_unix_socket_keeps_the_plugin_outside_key_custody() {
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("prover.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_sidecar_request(&mut stream).unwrap();
            assert_eq!(request.request_id, "socket-proof-1");
            stream.write_all(br#"{"status":"invalid"}"#).unwrap();
        });
        let response = request_proof_over_socket(
            &socket,
            &directory.path().join("source.json"),
            "socket-proof-1",
        )
        .unwrap();
        assert_eq!(response, br#"{"status":"invalid"}"#);
        server.join().unwrap();
    }
}
