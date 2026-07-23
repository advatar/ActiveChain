//! Generates the frozen development vectors from typed protocol values.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use activechain_action_kernel::{
    ACTION_PROTOCOL_VERSION, ActionEnvelope, FeeTicket, NonceAdvanceError, NonceChannel,
    ResourcePrices, ResourceVector, ValidityInterval, action_id,
};
use activechain_bytecode_verifier::{
    VmInstruction, VmProgram, VmValueType, VmVerificationError, verify,
};
use activechain_canonical_codec::{
    CanonicalType, canonical_length_prefix_len, encode_body, encode_envelope,
};
use activechain_capability::verify_attenuation;
use activechain_credential::{
    CredentialStatus, CredentialVerificationError, PresentationContext, PreverifiedIssuerEvidence,
    PreverifiedStatusEvidence, canonical_schema_facts, credential_id,
    credential_issuance_commitment, verify_presentation,
};
use activechain_devnet_kernel::{BlockReceipt, ChainState, DevnetBlock, apply_block};
use activechain_object::{ObjectTransitionError, transfer_object};
use activechain_object_vm::{VmEventValue, VmExecutionResult, VmValue, execute};
use activechain_policy_kernel::{
    APL_LANGUAGE_VERSION, ActorBinding, ApprovalFact, DecisionResult, PolicyDecision, PolicyEffect,
    PolicyObligation, PolicyPredicate, PolicyRequest, PolicyRequestFields, PolicyRule, PolicySet,
    combine_effects, evaluate,
};
use activechain_principal::{
    LifecycleAuthorization, PrincipalCommand, PrincipalGenesis, apply_lifecycle_command,
    create_principal,
};
use activechain_privacy_kernel::{
    DomainPseudonymOpening, NullifierOpening, NullifierSet, PrivateCredentialPresentation,
    ShieldedCashState, ShieldedNote, ShieldedTransferPublicInputs, VerifiedPrivacyProof,
};
use activechain_protocol_commitment::{DomainTag, commit};
use activechain_protocol_types::{
    AccessManifest, AccessManifestFields, ActionId, AuthenticatorDescriptor, AuthenticatorId,
    AuthenticatorPurpose, BoundedActionSet, CREDENTIAL_FORMAT_VERSION, CapabilityGrant,
    CapabilityGrantFields, CapabilityId, ChainId, ConsensusState, ConsensusUpgradeAuthorization,
    ConsensusVoteContext, Credential, CredentialAcceptancePolicy, CredentialId,
    CredentialStatement, CredentialStatusRegistry, CryptoSuiteId, DataSelector, Digest384,
    FreezeState, HolderBinding, Object, ObjectFields, ObjectFlags, ObjectId, ObjectOwner,
    ObjectVersionRef, Principal, PrincipalId, PrincipalKind, ProtocolSignature, QuorumCertificate,
    RateLimit, RecoveryRequest, ResourceSelector,
};
use activechain_state_tree::{
    StateCommitment, StateProof, commit_objects, partition_id, path_nibble, prove_object,
    verify_membership, verify_non_membership,
};
use activechain_transition::{
    ObjectState, ReceiptResult, TRANSFER_OBJECT_ACTION_ID, TransferCommand, TransferTransaction,
    TransitionReceipt, apply_transfer_transaction,
};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Shake256, digest::ExtendableOutput, digest::Update, digest::XofReader};

fn vector_files(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("vector directory is readable") {
        let path = entry.expect("vector entry is readable").path();
        if path.is_dir() {
            vector_files(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "txt") {
            output.push(path);
        }
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "hex length is even");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid vector hex digit"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn commitment_from_envelope(
    envelope: &[u8],
    type_tag: u16,
    schema_version: u16,
    body_length: usize,
) -> [u8; 48] {
    let body = activechain_canonical_codec::inspect_canonical_envelope(
        envelope,
        type_tag,
        schema_version,
        body_length,
    )
    .expect("published envelope has strict framing")
    .body();
    let mut transcript = Vec::with_capacity(38 + body.len());
    transcript.extend_from_slice(b"ACTIVECHAIN-COMMITMENT");
    transcript.extend_from_slice(&1_u16.to_be_bytes());
    transcript.extend_from_slice(&DomainTag::CANONICAL_VALUE.as_u16().to_be_bytes());
    transcript.extend_from_slice(&type_tag.to_be_bytes());
    transcript.extend_from_slice(&schema_version.to_be_bytes());
    transcript.extend_from_slice(&(body.len() as u64).to_be_bytes());
    transcript.extend_from_slice(body);
    let mut hasher = Shake256::default();
    hasher.update(&transcript);
    let mut commitment = [0; 48];
    hasher.finalize_xof().read(&mut commitment);
    commitment
}

fn render_envelope_manifest_v1() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors");
    let mut files = Vec::new();
    vector_files(&root, &mut files);
    files.sort();
    let mut entries = Vec::new();

    for path in files {
        let text = fs::read_to_string(&path).expect("text vector is UTF-8");
        let fields: BTreeMap<_, _> = text
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.trim(), value.trim()))
            .collect();
        for (key, value) in &fields {
            let Some(prefix) = key.strip_suffix("envelope_hex") else {
                continue;
            };
            let metadata_prefix = prefix.strip_suffix('_').unwrap_or(prefix);
            let field = |suffix: &str| {
                if metadata_prefix.is_empty() {
                    suffix.to_owned()
                } else {
                    format!("{metadata_prefix}_{suffix}")
                }
            };
            let type_tag_text = fields[&*field("type_tag")];
            let type_tag = u16::from_str_radix(type_tag_text.trim_start_matches("0x"), 16).unwrap();
            let schema_version: u16 = fields[&*field("schema_version")].parse().unwrap();
            let body_length: usize = fields[&*field("body_length")].parse().unwrap();
            let envelope = decode_hex(value);
            let commitment_key = field("canonical_value_commitment_hex");
            let commitment = fields
                .get(commitment_key.as_str())
                .unwrap_or_else(|| panic!("{} {key} has no commitment", path.display()));
            assert_eq!(
                hexadecimal(&commitment_from_envelope(
                    &envelope,
                    type_tag,
                    schema_version,
                    body_length,
                )),
                *commitment,
                "{} {key} commitment drift",
                path.display()
            );
            let source = path
                .strip_prefix(&root)
                .expect("vector is below root")
                .to_string_lossy()
                .replace('\\', "/");
            let envelope_sha256 = hexadecimal(&Sha256::digest(&envelope));
            entries.push((
                source,
                (*key).to_owned(),
                type_tag_text.to_owned(),
                schema_version,
                envelope_sha256,
                (*commitment).to_owned(),
            ));
        }
    }
    entries.sort();
    let mut output = String::from(
        "{\n  \"manifest\": \"activechain-envelope-hashes-v1\",\n  \"envelopes\": [\n",
    );
    for (index, (source, field, type_tag, schema, sha256, commitment)) in entries.iter().enumerate()
    {
        output.push_str(&format!(
            "    {{\n      \"source\": \"{source}\",\n      \"field\": \"{field}\",\n      \
             \"type_tag\": \"{type_tag}\",\n      \"schema_version\": {schema},\n      \
             \"envelope_sha256\": \"{sha256}\",\n      \
             \"canonical_value_commitment\": \"{commitment}\"\n    }}{}\n",
            if index + 1 == entries.len() { "" } else { "," }
        ));
    }
    output.push_str("  ]\n}\n");
    output
}

fn repeated_digest(byte: u8) -> Digest384 {
    Digest384::new([byte; 48])
}

fn certify_upgrade_height(state: &mut ConsensusState, height: u64) {
    let context = ConsensusVoteContext::new_with_revision(
        repeated_digest(0xfe),
        state.epoch(),
        state.validator_set_root(),
        state.protocol_revision(),
    )
    .expect("upgrade trace context is bound");
    let qc = QuorumCertificate::new(
        context,
        height,
        height,
        repeated_digest((height as u8).wrapping_add(1)),
        repeated_digest((height as u8).wrapping_add(2)),
        1,
        1,
    )
    .expect("single validator trace QC is a strict quorum");
    state.apply_qc(&qc).expect("trace QC advances the production state");
}

fn upgrade_authorization(
    state: &ConsensusState,
    next_epoch: u64,
    next_root: Digest384,
    next_revision: u64,
) -> ConsensusUpgradeAuthorization {
    ConsensusUpgradeAuthorization::new(
        state.finalized_height(),
        state.finalized_height() + 1,
        state.epoch(),
        next_epoch,
        state.validator_set_root(),
        next_root,
        state.protocol_revision(),
        next_revision,
    )
    .expect("upgrade trace authorization is structurally valid")
}

fn render_upgrade_result(name: &str, state: ConsensusState, accepted: bool) -> String {
    if accepted {
        format!(
            "{name},accept,{},{},{}\n",
            state.epoch(),
            state.protocol_revision(),
            state.retired_validator_set_roots().len()
        )
    } else {
        format!("{name},reject,-,-,-\n")
    }
}

fn render_epoch_upgrade_model_table() -> String {
    let base = || {
        let mut state = ConsensusState::new_with_validator_set_root(1, repeated_digest(1));
        certify_upgrade_height(&mut state, 1);
        state
    };
    let mut output = String::new();

    let mut validator = base();
    let auth = upgrade_authorization(&validator, 2, repeated_digest(2), 1);
    let accepted = validator.apply_upgrade(&auth).is_ok();
    output.push_str(&render_upgrade_result("validator_set", validator, accepted));

    let mut protocol = base();
    let auth = upgrade_authorization(&protocol, 1, repeated_digest(1), 2);
    let accepted = protocol.apply_upgrade(&auth).is_ok();
    output.push_str(&render_upgrade_result("protocol", protocol, accepted));

    let mut combined = base();
    let auth = upgrade_authorization(&combined, 2, repeated_digest(2), 2);
    let accepted = combined.apply_upgrade(&auth).is_ok();
    output.push_str(&render_upgrade_result("combined", combined, accepted));

    let mut wrong_height = base();
    let auth = ConsensusUpgradeAuthorization::new(
        1,
        3,
        1,
        2,
        repeated_digest(1),
        repeated_digest(2),
        1,
        1,
    )
    .unwrap();
    let accepted = wrong_height.apply_upgrade(&auth).is_ok();
    output.push_str(&render_upgrade_result("wrong_height", wrong_height, accepted));

    let mut stale_context = base();
    let auth = ConsensusUpgradeAuthorization::new(
        1,
        2,
        1,
        2,
        repeated_digest(9),
        repeated_digest(2),
        1,
        1,
    )
    .unwrap();
    let accepted = stale_context.apply_upgrade(&auth).is_ok();
    output.push_str(&render_upgrade_result("stale_context", stale_context, accepted));

    let downgrade = ConsensusUpgradeAuthorization::new(
        1,
        2,
        1,
        1,
        repeated_digest(1),
        repeated_digest(1),
        2,
        1,
    )
    .is_ok();
    output.push_str(&render_upgrade_result("revision_downgrade", base(), downgrade));

    let mut retired = base();
    let first = upgrade_authorization(&retired, 2, repeated_digest(2), 1);
    retired.apply_upgrade(&first).unwrap();
    certify_upgrade_height(&mut retired, 2);
    let reactivation = upgrade_authorization(&retired, 3, repeated_digest(1), 1);
    let accepted = retired.apply_upgrade(&reactivation).is_ok();
    output.push_str(&render_upgrade_result("retired_root", retired, accepted));

    let mut full = base();
    for index in 0..activechain_protocol_types::MAX_RETIRED_VALIDATOR_SET_ROOTS {
        let next_epoch = full.epoch() + 1;
        let next_root = repeated_digest((index as u8).wrapping_add(2));
        let auth = upgrade_authorization(&full, next_epoch, next_root, 1);
        full.apply_upgrade(&auth).unwrap();
        certify_upgrade_height(&mut full, index as u64 + 2);
    }
    let auth = upgrade_authorization(&full, full.epoch() + 1, repeated_digest(200), 1);
    let accepted = full.apply_upgrade(&auth).is_ok();
    output.push_str(&render_upgrade_result("history_full", full, accepted));
    output
}

fn render_codec_length_table() -> String {
    let mut output = String::new();
    for value in
        [0_u32, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152, 268_435_455, 268_435_456, u32::MAX]
    {
        output.push_str(&format!("{value},{}\n", canonical_length_prefix_len(value)));
    }
    output
}

fn principal_v1() -> Principal {
    Principal::new(
        PrincipalId::new(repeated_digest(0x11)),
        PrincipalKind::Agent,
        repeated_digest(0x22),
        repeated_digest(0x33),
        repeated_digest(0x44),
        7,
        FreezeState::Active,
        repeated_digest(0x55),
        1_000,
        42,
        43,
    )
    .expect("the source vector must satisfy the Principal v1 schema")
}

fn hexadecimal(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn render_principal_v1() -> String {
    let principal = principal_v1();
    let body = encode_body(&principal).expect("Principal v1 body must fit its declared bound");
    let envelope =
        encode_envelope(&principal).expect("Principal v1 envelope must fit its declared bound");
    let commitment = commit(DomainTag::CANONICAL_VALUE, &principal)
        .expect("Principal v1 commitment input must encode");

    format!(
        "# ActiveChain canonical vector\n\
# Generated by: cargo run --locked --quiet -p activechain-vector-generator\n\
# Transcript: P-001 draft 0.1\n\
\n\
vector=principal-v1\n\
type_tag=0x{:04x}\n\
schema_version={}\n\
\n\
principal_id=11 repeated 48 times\n\
principal_kind=Agent (4)\n\
controller_policy_hash=22 repeated 48 times\n\
recovery_policy_hash=33 repeated 48 times\n\
authenticator_set_root=44 repeated 48 times\n\
sequence=7\n\
freeze_state=Active (0)\n\
metadata_commitment=55 repeated 48 times\n\
anchor_deposit=1000\n\
created_at=42\n\
last_updated_at=43\n\
\n\
body_length={}\n\
body_hex={}\n\
envelope_hex={}\n\
commitment_domain=canonical-value (0x0001)\n\
canonical_value_commitment_hex={}\n",
        Principal::TYPE_TAG,
        Principal::SCHEMA_VERSION,
        body.len(),
        hexadecimal(&body),
        hexadecimal(&envelope),
        hexadecimal(commitment.as_bytes())
    )
}

fn identifier_principal(byte: u8) -> PrincipalId {
    PrincipalId::new(repeated_digest(byte))
}

fn identifier_capability(byte: u8) -> CapabilityId {
    CapabilityId::new(repeated_digest(byte))
}

fn identifier_action(byte: u8) -> ActionId {
    ActionId::new(repeated_digest(byte))
}

fn encoded_value<T: CanonicalType>(name: &str, value: &T) -> String {
    let body = encode_body(value).expect("vector body must fit its declared bound");
    let envelope = encode_envelope(value).expect("vector envelope must fit its declared bound");
    let commitment =
        commit(DomainTag::CANONICAL_VALUE, value).expect("vector commitment input must encode");
    format!(
        "{name}_type_tag=0x{:04x}\n\
{name}_schema_version={}\n\
{name}_body_length={}\n\
{name}_body_hex={}\n\
{name}_envelope_hex={}\n\
{name}_canonical_value_commitment_hex={}\n",
        T::TYPE_TAG,
        T::SCHEMA_VERSION,
        body.len(),
        hexadecimal(&body),
        hexadecimal(&envelope),
        hexadecimal(commitment.as_bytes()),
    )
}

fn render_privacy_v1() -> String {
    let chain_id = ChainId::new(repeated_digest(0x11));
    let asset_id = activechain_protocol_types::AssetId::new(repeated_digest(0x22));
    let note = ShieldedNote::new(
        chain_id,
        asset_id,
        repeated_digest(0x33),
        500,
        repeated_digest(0x44),
        repeated_digest(0x55),
    )
    .expect("privacy vector note is valid");
    let note_commitment = note.commitment().expect("privacy vector note commits");
    let nullifier = NullifierOpening::new(chain_id, note_commitment, repeated_digest(0x66), 7)
        .nullifier()
        .expect("privacy vector nullifier commits");
    let inputs = ShieldedTransferPublicInputs::new(
        chain_id,
        repeated_digest(0x77),
        asset_id,
        repeated_digest(0x88),
        vec![nullifier],
        vec![repeated_digest(0x99)],
        5,
        1_000,
    )
    .expect("privacy vector inputs are valid");
    let public_inputs_commitment = inputs.commitment().expect("privacy vector inputs commit");
    let proof = VerifiedPrivacyProof { public_inputs_commitment, verified: true };
    assert!(proof.verified);
    let state = ShieldedCashState::new(
        500,
        public_inputs_commitment,
        NullifierSet::new(vec![nullifier]).expect("privacy vector nullifier set is canonical"),
    )
    .expect("privacy vector state is valid");
    let pseudonym =
        DomainPseudonymOpening::new(chain_id, repeated_digest(0xaa), repeated_digest(0xbb), 7)
            .expect("privacy vector pseudonym opening is valid")
            .pseudonym()
            .expect("privacy vector pseudonym commits");
    let presentation = PrivateCredentialPresentation::new(
        chain_id,
        repeated_digest(0xaa),
        pseudonym,
        identifier_principal(0xcc),
        repeated_digest(0xdd),
        repeated_digest(0xde),
        repeated_digest(0xef),
        9,
        900,
        100,
        repeated_digest(0xf0),
        repeated_digest(0xf1),
        1_050,
    )
    .expect("privacy vector credential presentation is valid");

    format!(
        "# ActiveChain bounded privacy vector v1\n\
note_commitment_hex={}\n\
nullifier_hex={}\n\
public_inputs_commitment_hex={}\n\
domain_pseudonym_hex={}\n\
{}{}{}{}",
        hexadecimal(note_commitment.as_bytes()),
        hexadecimal(nullifier.as_bytes()),
        hexadecimal(public_inputs_commitment.as_bytes()),
        hexadecimal(pseudonym.as_bytes()),
        encoded_value("note", &note),
        encoded_value("public_inputs", &inputs),
        encoded_value("shielded_state", &state),
        encoded_value("private_credential", &presentation),
    )
}

fn authority_authenticator() -> AuthenticatorDescriptor {
    AuthenticatorDescriptor::new(
        AuthenticatorId::new(repeated_digest(0x66)),
        CryptoSuiteId::ML_DSA_65,
        vec![0x77; 1_952],
        AuthenticatorPurpose::Control,
        42,
        Some(1_000),
        None,
    )
    .expect("authority vector authenticator is valid")
}

fn authority_lifecycle() -> (Principal, Principal, Principal, RecoveryRequest) {
    let genesis = PrincipalGenesis {
        principal_id: identifier_principal(0x11),
        principal_kind: PrincipalKind::Agent,
        controller_policy_hash: repeated_digest(0x22),
        recovery_policy_hash: repeated_digest(0x33),
        authenticator_set_root: repeated_digest(0x44),
        metadata_commitment: repeated_digest(0x55),
        anchor_deposit: 1_000,
    };
    let created = create_principal(genesis, 42, 500).expect("authority genesis is valid");

    let controller = LifecycleAuthorization::controller(
        created.principal_id(),
        created.sequence(),
        created.controller_policy_hash(),
    );
    let rotation_output = apply_lifecycle_command(
        &created,
        PrincipalCommand::RotateController {
            expected_sequence: 0,
            new_controller_policy_hash: repeated_digest(0x23),
            new_authenticator_set_root: repeated_digest(0x45),
        },
        Some(&controller),
        43,
    )
    .expect("authority rotation is valid");
    let rotated = rotation_output.principal();
    assert_eq!(rotation_output.recovery_request(), None);

    let controller = LifecycleAuthorization::controller(
        rotated.principal_id(),
        rotated.sequence(),
        rotated.controller_policy_hash(),
    );
    let freeze_output = apply_lifecycle_command(
        &rotated,
        PrincipalCommand::Freeze { expected_sequence: 1 },
        Some(&controller),
        44,
    )
    .expect("authority freeze is valid");
    let frozen = freeze_output.principal();
    assert_eq!(freeze_output.recovery_request(), None);

    let recovery = LifecycleAuthorization::recovery(
        frozen.principal_id(),
        frozen.sequence(),
        frozen.recovery_policy_hash(),
    );
    let recovery_output = apply_lifecycle_command(
        &frozen,
        PrincipalCommand::InitiateRecovery {
            expected_sequence: 2,
            proposed_controller_policy_hash: repeated_digest(0x24),
            proposed_authenticator_set_root: repeated_digest(0x46),
            recovery_evidence_commitment: repeated_digest(0x88),
            challenge_deadline: 55,
            recovery_bond: 250,
        },
        Some(&recovery),
        45,
    )
    .expect("authority recovery initiation is valid");
    let pending = recovery_output.principal();
    let request = recovery_output.recovery_request().expect("recovery vector must produce request");

    (created, rotated, pending, request)
}

fn authority_signature(byte: u8) -> ProtocolSignature {
    ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![byte; 2_420])
        .expect("authority vector signature has canonical structure")
}

fn authority_capabilities() -> (CapabilityGrant, CapabilityGrant) {
    let revocation_registry = ObjectId::new(repeated_digest(0x93));
    let constraint_hash = repeated_digest(0x94);
    let parent = CapabilityGrant::new(
        CapabilityGrantFields {
            capability_id: identifier_capability(0x90),
            issuer: identifier_principal(0x91),
            holder_binding: HolderBinding::Principal(identifier_principal(0x92)),
            parent_capability: None,
            permitted_actions: BoundedActionSet::new(vec![
                identifier_action(0x01),
                identifier_action(0x02),
            ])
            .expect("authority vector actions are sorted"),
            resource_scope: ResourceSelector::ANY,
            data_scope: DataSelector::ANY,
            monetary_limit: Some(1_000),
            compute_limit: Some(10_000),
            rate_limit: Some(RateLimit::new(100, 50).expect("non-zero rate")),
            use_limit: Some(500),
            valid_from: 10,
            valid_until: Some(1_000),
            delegation_depth_remaining: 2,
            delegation_allowed: true,
            revocation_registry: Some(revocation_registry),
            constraint_hash,
        },
        authority_signature(0x95),
    )
    .expect("authority parent grant is valid");

    let child = CapabilityGrant::new(
        CapabilityGrantFields {
            capability_id: identifier_capability(0x96),
            issuer: identifier_principal(0x92),
            holder_binding: HolderBinding::Principal(identifier_principal(0x97)),
            parent_capability: Some(identifier_capability(0x90)),
            permitted_actions: BoundedActionSet::new(vec![identifier_action(0x01)])
                .expect("authority vector child action is valid"),
            resource_scope: ResourceSelector::exact(ObjectId::new(repeated_digest(0x98))),
            data_scope: DataSelector::exact(repeated_digest(0x99)),
            monetary_limit: Some(500),
            compute_limit: Some(5_000),
            rate_limit: Some(RateLimit::new(50, 50).expect("non-zero rate")),
            use_limit: Some(100),
            valid_from: 20,
            valid_until: Some(900),
            delegation_depth_remaining: 1,
            delegation_allowed: true,
            revocation_registry: Some(revocation_registry),
            constraint_hash,
        },
        authority_signature(0x9a),
    )
    .expect("authority child grant is valid");
    verify_attenuation(&parent, &child).expect("authority child is mechanically attenuated");
    (parent, child)
}

fn render_authority_v1() -> String {
    let authenticator = authority_authenticator();
    let (created, rotated, pending, recovery_request) = authority_lifecycle();
    let (parent, child) = authority_capabilities();

    let mut output = String::from(
        "# ActiveChain authority vector\n\
# Generated by: cargo run --locked --quiet -p activechain-vector-generator -- authority-v1\n\
# Transcripts: P-001/P-002/P-020/P-022 draft 0.1\n\
\n\
vector=authority-v1\n\
commitment_domain=canonical-value (0x0001)\n\
\n",
    );
    output.push_str(&encoded_value("authenticator", &authenticator));
    output.push('\n');
    output.push_str(&encoded_value("created_principal", &created));
    output.push('\n');
    output.push_str(&encoded_value("rotated_principal", &rotated));
    output.push('\n');
    output.push_str(&encoded_value("recovery_pending_principal", &pending));
    output.push('\n');
    output.push_str(&encoded_value("recovery_request", &recovery_request));
    output.push('\n');
    output.push_str(&encoded_value("parent_capability", &parent));
    output.push('\n');
    output.push_str(&encoded_value("child_capability", &child));
    output.push_str("\nattenuation_result=permit\n");
    output
}

fn apl_values() -> (PolicySet, PolicyRequest, PolicyDecision) {
    let actor = ActorBinding::Principal(identifier_principal(0x10));
    let action = identifier_action(0x20);
    let resource = ObjectId::new(repeated_digest(0x30));
    let purpose = repeated_digest(0x40);
    let credential_schema = repeated_digest(0x50);
    let capability_id = identifier_capability(0x60);
    let approval_role = repeated_digest(0x70);

    let policy = PolicySet::new(
        APL_LANGUAGE_VERSION,
        vec![
            PolicyRule::new(
                PolicyEffect::Permit,
                vec![
                    PolicyPredicate::ActorIs(actor),
                    PolicyPredicate::ActionIs(action),
                    PolicyPredicate::ResourceMatches(ResourceSelector::exact(resource)),
                    PolicyPredicate::ValueAtMost(1_000),
                    PolicyPredicate::HeightAtLeast(40),
                    PolicyPredicate::HasCredentialSchema(credential_schema),
                    PolicyPredicate::HasCapability(capability_id),
                    PolicyPredicate::ApprovalCountAtLeast { role: approval_role, minimum: 2 },
                    PolicyPredicate::FreezeStateIs(FreezeState::Active),
                    PolicyPredicate::DeclaredPurposeIs(purpose),
                ],
                vec![
                    PolicyObligation::DecrementCapabilityBudget { capability_id, amount: 500 },
                    PolicyObligation::ConsumeCapability(capability_id),
                    PolicyObligation::EmitAuditCommitment(repeated_digest(0x80)),
                    PolicyObligation::RequireApproval { role: approval_role, minimum: 2 },
                ],
            )
            .expect("APL vector permit rule is valid"),
            PolicyRule::new(
                PolicyEffect::Permit,
                vec![PolicyPredicate::ValueAtLeast(100), PolicyPredicate::HeightAtMost(60)],
                vec![
                    PolicyObligation::DelaySettlementUntil(55),
                    PolicyObligation::RestrictOutputDisclosure(repeated_digest(0x90)),
                ],
            )
            .expect("APL vector secondary permit rule is valid"),
            PolicyRule::new(
                PolicyEffect::Forbid,
                vec![PolicyPredicate::FreezeStateIs(FreezeState::Frozen)],
                vec![],
            )
            .expect("APL vector forbid rule is valid"),
        ],
    )
    .expect("APL vector policy is bounded");

    let request = PolicyRequest::new(PolicyRequestFields {
        actor,
        action,
        resource,
        height: 50,
        value: 500,
        freeze_state: FreezeState::Active,
        declared_purpose: Some(purpose),
        credential_schemas: vec![credential_schema],
        capabilities: vec![capability_id],
        approvals: vec![ApprovalFact::new(approval_role, 2).expect("non-zero approval count")],
    })
    .expect("APL vector request facts are canonical");

    let decision = evaluate(&policy, &request);
    assert_eq!(decision.result(), DecisionResult::Permit);
    assert_eq!(decision.matched_permit_rules(), 2);
    assert_eq!(decision.matched_forbid_rules(), 0);
    assert_eq!(decision.steps_used(), 16);
    assert_eq!(decision.obligations().len(), 6);
    (policy, request, decision)
}

fn render_apl_v1() -> String {
    let (policy, request, decision) = apl_values();
    let mut output = String::from(
        "# ActiveChain APL vector\n\
# Generated by: cargo run --locked --quiet -p activechain-vector-generator -- apl-v1\n\
# Transcripts: P-001/P-023 draft 0.1\n\
\n\
vector=apl-v1\n\
commitment_domain=canonical-value (0x0001)\n\
actor=Principal(10 repeated 48 times)\n\
action=20 repeated 48 times\n\
resource=30 repeated 48 times\n\
height=50\n\
value=500\n\
decision=Permit\n\
matched_permit_rules=2\n\
matched_forbid_rules=0\n\
steps_used=16\n\
obligation_count=6\n\
\n",
    );
    output.push_str(&encoded_value("policy", &policy));
    output.push('\n');
    output.push_str(&encoded_value("request", &request));
    output.push('\n');
    output.push_str(&encoded_value("decision", &decision));
    output
}

fn render_apl_truth_table() -> String {
    let mut output = String::new();
    for (has_permit, has_forbid) in [(false, false), (false, true), (true, false), (true, true)] {
        let result = match combine_effects(has_permit, has_forbid) {
            DecisionResult::Deny => "Deny",
            DecisionResult::Permit => "Permit",
        };
        output.push_str(if has_permit { "true" } else { "false" });
        output.push(',');
        output.push_str(if has_forbid { "true" } else { "false" });
        output.push(',');
        output.push_str(result);
        output.push('\n');
    }
    output
}

fn object_transition_values() -> (
    Object,
    AccessManifest,
    ObjectState,
    TransferTransaction,
    TransitionReceipt,
    Object,
    ObjectState,
) {
    let object_id = ObjectId::new(repeated_digest(0xa0));
    let actor = ActorBinding::Principal(identifier_principal(0xb1));
    let policy = PolicySet::new(
        APL_LANGUAGE_VERSION,
        vec![
            PolicyRule::new(
                PolicyEffect::Permit,
                vec![
                    PolicyPredicate::ActorIs(actor),
                    PolicyPredicate::ActionIs(TRANSFER_OBJECT_ACTION_ID),
                    PolicyPredicate::ResourceMatches(ResourceSelector::exact(object_id)),
                    PolicyPredicate::FreezeStateIs(FreezeState::Active),
                ],
                vec![],
            )
            .expect("object vector control rule is valid"),
        ],
    )
    .expect("object vector policy is bounded");
    let control_policy_hash =
        commit(DomainTag::CANONICAL_VALUE, &policy).expect("object vector control policy encodes");
    let object = Object::new(ObjectFields {
        object_id,
        object_version: 7,
        type_id: repeated_digest(0xa1),
        owner: ObjectOwner::Principal(identifier_principal(0xb1)),
        control_policy_hash,
        use_policy_hash: repeated_digest(0xa2),
        disclosure_policy_hash: repeated_digest(0xa3),
        upgrade_policy_hash: repeated_digest(0xa4),
        package_id: None,
        value_root: repeated_digest(0xa5),
        public_value: Some(b"activechain-object-v1".to_vec()),
        lease_expiry_epoch: 100,
        storage_deposit: 5_000,
        flags: ObjectFlags::TRANSFERABLE.union(ObjectFlags::LINEAR),
    })
    .expect("object vector value is canonical");
    let input = ObjectVersionRef::new(object_id, 7);
    let manifest = AccessManifest::new(AccessManifestFields {
        exact_reads: vec![],
        exact_writes: vec![input],
        immutable_reads: vec![],
        creation_namespaces: vec![],
        maximum_created_objects: 0,
        maximum_dynamic_reads: 0,
        dynamic_read_policy: None,
    })
    .expect("object vector manifest is canonical");
    let request = PolicyRequest::new(PolicyRequestFields {
        actor,
        action: TRANSFER_OBJECT_ACTION_ID,
        resource: object_id,
        height: 50,
        value: 0,
        freeze_state: FreezeState::Active,
        declared_purpose: None,
        credential_schemas: vec![],
        capabilities: vec![],
        approvals: vec![],
    })
    .expect("object vector request is canonical");
    let transaction = TransferTransaction::new(
        50,
        manifest.clone(),
        vec![TransferCommand::new(
            input,
            ObjectOwner::Shielded(repeated_digest(0xb0)),
            policy,
            request,
        )],
    )
    .expect("object vector transaction is canonical");
    let pre_state = ObjectState::new(vec![object.clone()]).expect("object vector state is ordered");
    let output = apply_transfer_transaction(&pre_state, &transaction)
        .expect("object vector transition is structurally valid");
    assert_eq!(output.receipt().result(), ReceiptResult::Success);
    assert_eq!(output.receipt().objects_updated(), 1);
    assert_eq!(output.receipt().policy_steps(), 5);
    let post_object =
        output.state().find(object_id).expect("transition preserves object identity").clone();
    assert_eq!(post_object.object_version(), 8);
    (
        object,
        manifest,
        pre_state,
        transaction,
        output.receipt(),
        post_object,
        output.state().clone(),
    )
}

fn render_object_transition_v1() -> String {
    let (object, manifest, pre_state, transaction, receipt, post_object, post_state) =
        object_transition_values();
    let mut output = String::from(
        "# ActiveChain object transition vector\n\
# Generated by: cargo run --locked --quiet -p activechain-vector-generator -- object-transition-v1\n\
# Transcripts: P-001/P-010/P-023/P-030 draft\n\
\n\
vector=object-transition-v1\n\
commitment_domain=canonical-value (0x0001)\n\
object_id=a0 repeated 48 times\n\
object_version_before=7\n\
object_version_after=8\n\
new_owner=Shielded(b0 repeated 48 times)\n\
receipt=Success\n\
objects_updated=1\n\
policy_steps=5\n\
\n",
    );
    output.push_str(&encoded_value("object_before", &object));
    output.push('\n');
    output.push_str(&encoded_value("access_manifest", &manifest));
    output.push('\n');
    output.push_str(&encoded_value("pre_state", &pre_state));
    output.push('\n');
    output.push_str(&encoded_value("transfer_transaction", &transaction));
    output.push('\n');
    output.push_str(&encoded_value("transition_receipt", &receipt));
    output.push('\n');
    output.push_str(&encoded_value("object_after", &post_object));
    output.push('\n');
    output.push_str(&encoded_value("post_state", &post_state));
    output
}

fn model_object(version: u64) -> Object {
    Object::new(ObjectFields {
        object_id: ObjectId::new(repeated_digest(0xc0)),
        object_version: version,
        type_id: repeated_digest(0xc1),
        owner: ObjectOwner::Shared,
        control_policy_hash: Digest384::ZERO,
        use_policy_hash: Digest384::ZERO,
        disclosure_policy_hash: Digest384::ZERO,
        upgrade_policy_hash: Digest384::ZERO,
        package_id: None,
        value_root: Digest384::ZERO,
        public_value: None,
        lease_expiry_epoch: 0,
        storage_deposit: 0,
        flags: ObjectFlags::TRANSFERABLE,
    })
    .expect("model object is canonical")
}

fn render_object_model_table() -> String {
    let mut output = String::new();
    for (version, expected_version, authorized) in
        [(0, 0, true), (7, 6, true), (u64::MAX, u64::MAX, true), (7, 7, false)]
    {
        let result = if !authorized {
            String::from("AuthorizationDenied")
        } else {
            let object = model_object(version);
            match transfer_object(
                &object,
                ObjectVersionRef::new(object.object_id(), expected_version),
                ObjectOwner::Shielded(repeated_digest(0xc2)),
            ) {
                Ok(updated) => format!("Success({})", updated.object_version()),
                Err(ObjectTransitionError::StaleObjectVersion { .. }) => {
                    String::from("StaleObjectVersion")
                }
                Err(ObjectTransitionError::VersionExhausted) => String::from("VersionExhausted"),
                other => panic!("unexpected object model result: {other:?}"),
            }
        };
        output.push_str(&format!("{version},{expected_version},{authorized},{result}\n"));
    }
    output
}

fn state_tree_values() -> (StateCommitment, StateCommitment, Object, StateProof, StateProof) {
    let (member, _, _, _, _, _, _) = object_transition_values();
    let second = model_object(3);
    let objects = vec![member.clone(), second];
    let empty = commit_objects(&[]).expect("empty state commitment is defined");
    let commitment = commit_objects(&objects).expect("state vector objects are ordered");
    let membership = prove_object(&objects, member.object_id())
        .expect("state vector membership proof is constructible");
    verify_membership(commitment, &member, &membership)
        .expect("state vector membership proof verifies");

    let absent_id = ObjectId::new(repeated_digest(0xb0));
    let non_membership = prove_object(&objects, absent_id)
        .expect("state vector non-membership proof is constructible");
    verify_non_membership(commitment, absent_id, &non_membership)
        .expect("state vector non-membership proof verifies");
    (empty, commitment, member, membership, non_membership)
}

fn render_state_tree_v1() -> String {
    let (empty, commitment, member, membership, non_membership) = state_tree_values();
    let mut output = format!(
        "# ActiveChain sparse state-tree vector\n\
# Generated by: cargo run --locked --quiet -p activechain-vector-generator -- state-tree-v1\n\
# Transcripts: P-001/P-030/P-031 draft\n\
\n\
vector=state-tree-v1\n\
hash=SHAKE256/384\n\
arity=16\n\
depth=96\n\
object_count={}\n\
member_object_id=a0 repeated 48 times\n\
absent_object_id=b0 repeated 48 times\n\
membership_verification=success\n\
non_membership_verification=success\n\
empty_state_root_hex={}\n\
state_root_hex={}\n\
\n",
        commitment.object_count(),
        hexadecimal(empty.root().as_bytes()),
        hexadecimal(commitment.root().as_bytes()),
    );
    output.push_str(&encoded_value("empty_state_commitment", &empty));
    output.push('\n');
    output.push_str(&encoded_value("state_commitment", &commitment));
    output.push('\n');
    output.push_str(&encoded_value("member_object", &member));
    output.push('\n');
    output.push_str(&encoded_value("membership_proof", &membership));
    output.push('\n');
    output.push_str(&encoded_value("non_membership_proof", &non_membership));
    output
}

fn render_state_tree_model_table() -> String {
    let mut output = String::new();
    for (first, second, last) in [(0_u8, 0_u8, 0_u8), (18, 52, 239), (255, 255, 255)] {
        let mut bytes = [0_u8; 48];
        bytes[0] = first;
        bytes[1] = second;
        bytes[47] = last;
        let object_id = ObjectId::new(Digest384::new(bytes));
        output.push_str(&format!(
            "{first},{second},{last},{},{},{},{},{},{},{}\n",
            path_nibble(object_id, 0).expect("depth zero exists"),
            path_nibble(object_id, 1).expect("depth one exists"),
            path_nibble(object_id, 2).expect("depth two exists"),
            path_nibble(object_id, 3).expect("depth three exists"),
            path_nibble(object_id, 94).expect("depth 94 exists"),
            path_nibble(object_id, 95).expect("depth 95 exists"),
            partition_id(object_id),
        ));
    }
    output
}

fn object_vm_values() -> (VmProgram, Object, VmExecutionResult) {
    let (object, _, _, _, _, _, _) = object_transition_values();
    let program = VmProgram::new(
        3,
        vec![
            VmValueType::Object,
            VmValueType::Capability,
            VmValueType::U64,
            VmValueType::U64,
            VmValueType::U64,
            VmValueType::Bool,
            VmValueType::Digest,
            VmValueType::Object,
        ],
        vec![VmValueType::Object, VmValueType::U64, VmValueType::Bool],
        vec![
            VmInstruction::LoadU64 { destination: 3, value: 5 },
            VmInstruction::AddU64 { destination: 4, left: 2, right: 3 },
            VmInstruction::EqU64 { destination: 5, left: 4, right: 3 },
            VmInstruction::LoadDigest { destination: 6, value: repeated_digest(0xd1) },
            VmInstruction::Emit { source: 6 },
            VmInstruction::ConsumeCapability { source: 1 },
            VmInstruction::Move { destination: 7, source: 0 },
            VmInstruction::Return { sources: vec![7, 4, 5] },
        ],
        1,
    )
    .expect("ObjectVM vector program is structurally bounded");
    let verified = verify(program.clone()).expect("ObjectVM vector program verifies");
    let result = execute(
        &verified,
        vec![
            VmValue::Object(Box::new(object.clone())),
            VmValue::Capability(identifier_capability(0xd0)),
            VmValue::U64(7),
        ],
        16,
    )
    .expect("ObjectVM vector execution succeeds");
    assert_eq!(result.gas_used(), 16);
    assert_eq!(result.steps(), 8);
    assert_eq!(result.outputs()[1..], [VmValue::U64(12), VmValue::Bool(false)]);
    assert_eq!(result.events(), [VmEventValue::Digest(repeated_digest(0xd1))]);
    (program, object, result)
}

fn render_object_vm_v1() -> String {
    let (program, object, result) = object_vm_values();
    let mut output = String::from(
        "# ActiveChain ObjectVM vector\n\
# Generated by: cargo run --locked --quiet -p activechain-vector-generator -- object-vm-v1\n\
# Transcripts: P-001/P-030/P-050 draft\n\
\n\
vector=object-vm-v1\n\
program_verification=success\n\
input_0=Object(a0 repeated 48 times, version 7)\n\
input_1=Capability(d0 repeated 48 times)\n\
input_2=U64(7)\n\
gas_limit=16\n\
gas_used=16\n\
steps=8\n\
outputs=Object(a0 repeated 48 times, version 7),U64(12),Bool(false)\n\
events=Digest(d1 repeated 48 times)\n\
\n",
    );
    output.push_str(&encoded_value("program", &program));
    output.push('\n');
    output.push_str(&encoded_value("input_object", &object));
    output.push('\n');
    output.push_str(&encoded_value("execution_result", &result));
    output
}

#[derive(Clone, Copy)]
enum VmModelAction {
    Copy,
    Move,
    Consume,
}

fn vm_model_row(action: VmModelAction, value_type: VmValueType) -> String {
    let (register_types, output_types, instructions) = match action {
        VmModelAction::Copy => (
            vec![value_type, value_type],
            vec![value_type],
            vec![
                VmInstruction::Copy { destination: 1, source: 0 },
                VmInstruction::Return { sources: vec![1] },
            ],
        ),
        VmModelAction::Move => (
            vec![value_type, value_type],
            vec![value_type],
            vec![
                VmInstruction::Move { destination: 1, source: 0 },
                VmInstruction::Return { sources: vec![1] },
            ],
        ),
        VmModelAction::Consume => (
            vec![value_type],
            vec![],
            vec![
                VmInstruction::ConsumeCapability { source: 0 },
                VmInstruction::Return { sources: vec![] },
            ],
        ),
    };
    let gas_cost = instructions[0].gas_cost();
    let program = VmProgram::new(1, register_types, output_types, instructions, 0)
        .expect("ObjectVM model case is bounded");
    let verdict = match verify(program) {
        Ok(_) => "Accept",
        Err(VmVerificationError::CopyRequiresCopyable { .. }) => "CopyRequiresCopyable",
        Err(VmVerificationError::TypeMismatch { .. }) => "TypeMismatch",
        Err(other) => panic!("unexpected ObjectVM model verdict: {other:?}"),
    };
    let action = match action {
        VmModelAction::Copy => "Copy",
        VmModelAction::Move => "Move",
        VmModelAction::Consume => "Consume",
    };
    let value_type = match value_type {
        VmValueType::U64 => "U64",
        VmValueType::Bool => "Bool",
        VmValueType::Digest => "Digest",
        VmValueType::Object => "Object",
        VmValueType::Capability => "Capability",
    };
    format!("{action},{value_type},{verdict},{gas_cost}\n")
}

fn render_object_vm_model_table() -> String {
    let mut output = String::new();
    for (action, value_type) in [
        (VmModelAction::Copy, VmValueType::U64),
        (VmModelAction::Copy, VmValueType::Capability),
        (VmModelAction::Copy, VmValueType::Object),
        (VmModelAction::Consume, VmValueType::Capability),
        (VmModelAction::Consume, VmValueType::Object),
        (VmModelAction::Move, VmValueType::Object),
    ] {
        output.push_str(&vm_model_row(action, value_type));
    }
    output
}

fn devnet_values() -> (FeeTicket, NonceChannel, ActionEnvelope, DevnetBlock, BlockReceipt, Digest384)
{
    let (_, _, pre_state, transaction, _, _, _) = object_transition_values();
    let chain_id = ChainId::new(repeated_digest(0xe0));
    let sender = identifier_principal(0xb1);
    let maximum_resources = ResourceVector::new(100, 1, 1, 0, 0, 2_000_000);
    let fee_ticket = FeeTicket::new(
        ObjectId::new(repeated_digest(0xe1)),
        identifier_principal(0xe2),
        3_000_000,
        60,
        11,
        maximum_resources,
    )
    .expect("development vector fee ticket is valid");
    let payload_commitment = commit(DomainTag::CANONICAL_VALUE, &transaction)
        .expect("development vector payload encodes");
    let action = ActionEnvelope::new(
        ACTION_PROTOCOL_VERSION,
        chain_id,
        sender,
        fee_ticket,
        3,
        7,
        ValidityInterval::new(40, 60).expect("development vector validity is ordered"),
        maximum_resources,
        payload_commitment,
        transaction,
        repeated_digest(0xe4),
    )
    .expect("development vector action is valid");
    let nonce = NonceChannel::new(sender, 3, 7);
    let parent_block_id = repeated_digest(0xe3);
    let pre_state_commitment =
        commit_objects(pre_state.objects()).expect("development pre-state commits");
    let prices = ResourcePrices::new(1, 2, 3, 4, 5, 1);
    let state =
        ChainState::new(chain_id, 49, parent_block_id, pre_state, vec![nonce], vec![], prices)
            .expect("development vector chain state is canonical");
    let block =
        DevnetBlock::new(chain_id, 50, parent_block_id, pre_state_commitment, vec![action.clone()])
            .expect("development vector block is bounded");
    let output = apply_block(&state, &block).expect("development vector block applies");

    assert_eq!(output.state().height(), 50);
    assert_eq!(output.state().nonce_channels()[0].next_sequence(), 8);
    assert_eq!(output.state().used_fee_tickets(), [fee_ticket.ticket_id()]);
    assert_eq!(
        output
            .state()
            .objects()
            .find(ObjectId::new(repeated_digest(0xa0)))
            .expect("development vector object remains present")
            .object_version(),
        8,
    );
    (fee_ticket, nonce, action, block, output.receipt().clone(), output.receipt_root())
}

fn render_devnet_block_v1() -> String {
    let (fee_ticket, nonce, action, block, receipt, receipt_root) = devnet_values();
    let transaction_id = action_id(&action).expect("development vector action identifier encodes");
    let mut output = format!(
        "# ActiveChain semantic devnet vector\n\
# Generated by: cargo run --locked --quiet -p activechain-vector-generator -- devnet-block-v1\n\
# Transcripts: P-001/P-010/P-030/P-040 draft\n\
\n\
vector=devnet-block-v1\n\
chain_id=e0 repeated 48 times\n\
height=50\n\
parent_block_id=e3 repeated 48 times\n\
action_count=1\n\
action_id_hex={}\n\
block_id_hex={}\n\
post_state_root_hex={}\n\
receipt_root_hex={}\n\
nonce_next_sequence=8\n\
used_fee_ticket_count=1\n\
object_version_after=8\n\
\n",
        hexadecimal(transaction_id.into_digest().as_bytes()),
        hexadecimal(receipt.block_id().as_bytes()),
        hexadecimal(receipt.post_state().root().as_bytes()),
        hexadecimal(receipt_root.as_bytes()),
    );
    output.push_str(&encoded_value("fee_ticket", &fee_ticket));
    output.push('\n');
    output.push_str(&encoded_value("nonce_channel", &nonce));
    output.push('\n');
    output.push_str(&encoded_value("action_envelope", &action));
    output.push('\n');
    output.push_str(&encoded_value("devnet_block", &block));
    output.push('\n');
    output.push_str(&encoded_value("block_receipt", &receipt));
    output
}

fn render_nonce_model_table() -> String {
    let mut output = String::new();
    for (expected, supplied) in [(5, 5), (5, 4), (5, 6), (u64::MAX, u64::MAX)] {
        let channel = NonceChannel::new(identifier_principal(0xf0), 0, expected);
        let result = match channel.advance(supplied) {
            Ok(next) => format!("Accepted({})", next.next_sequence()),
            Err(NonceAdvanceError::Replay { .. }) => String::from("Replay"),
            Err(NonceAdvanceError::SequenceGap { .. }) => String::from("SequenceGap"),
            Err(NonceAdvanceError::SequenceExhausted) => String::from("SequenceExhausted"),
        };
        output.push_str(&format!("{expected},{supplied},{result}\n"));
    }
    output
}

fn credential_values() -> (
    CredentialStatement,
    Credential,
    CredentialStatusRegistry,
    CredentialAcceptancePolicy,
    CredentialId,
    Digest384,
) {
    let issuer = identifier_principal(0xc1);
    let subject_binding = repeated_digest(0xc2);
    let schema_id = repeated_digest(0xc3);
    let registry_id = ObjectId::new(repeated_digest(0xc5));
    let statement = CredentialStatement::new(
        CREDENTIAL_FORMAT_VERSION,
        issuer,
        subject_binding,
        schema_id,
        repeated_digest(0xc4),
        40,
        900,
        Some(1_100),
        Some(registry_id),
        Some(repeated_digest(0xc6)),
        Some(repeated_digest(0xc7)),
    )
    .expect("credential vector statement is valid");
    let credential = Credential::new(
        statement,
        ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![0xc8; 3_309])
            .expect("credential vector signature is structurally valid"),
    )
    .expect("credential vector uses the issuance suite profile");
    let registry =
        CredentialStatusRegistry::new(registry_id, issuer, schema_id, repeated_digest(0xc9), 4, 45);
    let policy = CredentialAcceptancePolicy::new(vec![issuer], vec![schema_id], 5, true, true)
        .expect("credential vector policy is canonical");
    let issuance_commitment =
        credential_issuance_commitment(&statement).expect("credential statement commits");
    let id = credential_id(&credential).expect("credential vector identifier commits");
    let issuer_evidence = PreverifiedIssuerEvidence::new(
        issuer,
        issuance_commitment,
        CryptoSuiteId::ML_DSA_65,
        Some(repeated_digest(0xc6)),
    );
    let status_evidence = PreverifiedStatusEvidence::new(
        registry_id,
        id,
        registry.status_root(),
        registry.sequence(),
        CredentialStatus::Active,
    );
    let fact = verify_presentation(
        &credential,
        &policy,
        &issuer_evidence,
        Some(&registry),
        Some(&status_evidence),
        PresentationContext::new(subject_binding, 50, 1_000),
    )
    .expect("credential vector presentation verifies");
    assert_eq!(fact.credential_id(), id);
    assert_eq!(fact.status_registry_sequence(), Some(4));
    assert_eq!(canonical_schema_facts(&[fact]), Ok(vec![schema_id]));
    (statement, credential, registry, policy, id, issuance_commitment)
}

fn render_credential_v1() -> String {
    let (statement, credential, registry, policy, id, issuance_commitment) = credential_values();
    let mut output = format!(
        "# ActiveChain credential and status vector\n\
# Generated by: cargo run --locked --quiet -p activechain-vector-generator -- credential-v1\n\
# Transcripts: P-001/P-002/P-021 draft\n\
\n\
vector=credential-v1\n\
issuer=c1 repeated 48 times\n\
subject_binding=c2 repeated 48 times\n\
schema_id=c3 repeated 48 times\n\
status_registry=c5 repeated 48 times\n\
presentation_height=50\n\
presentation_timestamp=1000\n\
status_age=5\n\
status=Active\n\
verification=Accepted\n\
issuance_commitment_hex={}\n\
credential_id_hex={}\n\
apl_schema_fact=c3 repeated 48 times\n\
\n",
        hexadecimal(issuance_commitment.as_bytes()),
        hexadecimal(id.into_digest().as_bytes()),
    );
    output.push_str(&encoded_value("credential_statement", &statement));
    output.push('\n');
    output.push_str(&encoded_value("credential", &credential));
    output.push('\n');
    output.push_str(&encoded_value("status_registry", &registry));
    output.push('\n');
    output.push_str(&encoded_value("acceptance_policy", &policy));
    output
}

fn credential_status_name(status: CredentialStatus) -> &'static str {
    match status {
        CredentialStatus::Active => "Active",
        CredentialStatus::Revoked => "Revoked",
        CredentialStatus::Suspended => "Suspended",
    }
}

fn render_credential_status_table() -> String {
    let mut output = String::new();
    for (declares, requires, height, effective, maximum_age, status) in [
        (false, false, 50, 0, 5, CredentialStatus::Active),
        (false, true, 50, 0, 5, CredentialStatus::Active),
        (true, false, 50, 51, 5, CredentialStatus::Active),
        (true, false, 50, 44, 5, CredentialStatus::Active),
        (true, false, 50, 45, 5, CredentialStatus::Active),
        (true, true, 50, 45, 5, CredentialStatus::Revoked),
        (true, true, 50, 45, 5, CredentialStatus::Suspended),
    ] {
        let issuer = identifier_principal(0xc1);
        let schema = repeated_digest(0xc3);
        let registry_id = ObjectId::new(repeated_digest(0xc5));
        let statement = CredentialStatement::new(
            1,
            issuer,
            repeated_digest(0xc2),
            schema,
            repeated_digest(0xc4),
            40,
            900,
            Some(1_100),
            declares.then_some(registry_id),
            None,
            None,
        )
        .expect("credential status model statement is valid");
        let credential = Credential::new(
            statement,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![0xc8; 3_309])
                .expect("credential status model signature is valid"),
        )
        .expect("credential status model credential is valid");
        let policy = CredentialAcceptancePolicy::new(
            vec![issuer],
            vec![schema],
            maximum_age,
            requires,
            false,
        )
        .expect("credential status model policy is canonical");
        let issuer_evidence = PreverifiedIssuerEvidence::new(
            issuer,
            credential_issuance_commitment(&statement).expect("model statement commits"),
            CryptoSuiteId::ML_DSA_65,
            None,
        );
        let registry = declares.then(|| {
            CredentialStatusRegistry::new(
                registry_id,
                issuer,
                schema,
                repeated_digest(0xc9),
                4,
                effective,
            )
        });
        let status_evidence = registry.map(|registry| {
            PreverifiedStatusEvidence::new(
                registry_id,
                credential_id(&credential).expect("model credential commits"),
                registry.status_root(),
                registry.sequence(),
                status,
            )
        });
        let verdict = match verify_presentation(
            &credential,
            &policy,
            &issuer_evidence,
            registry.as_ref(),
            status_evidence.as_ref(),
            PresentationContext::new(repeated_digest(0xc2), height, 1_000),
        ) {
            Ok(_) => "Accepted",
            Err(CredentialVerificationError::StatusRequired) => "StatusRequired",
            Err(CredentialVerificationError::RegistryFromFuture { .. }) => "RegistryFromFuture",
            Err(CredentialVerificationError::RegistryStale { .. }) => "RegistryStale",
            Err(CredentialVerificationError::CredentialRevoked) => "Revoked",
            Err(CredentialVerificationError::CredentialSuspended) => "Suspended",
            other => panic!("unexpected credential status model result: {other:?}"),
        };
        output.push_str(&format!(
            "{declares},{requires},{height},{effective},{maximum_age},{},{}\n",
            credential_status_name(status),
            verdict,
        ));
    }
    output
}

fn main() {
    let vector = std::env::args().nth(1);
    match vector.as_deref().unwrap_or("principal-v1") {
        "principal-v1" => print!("{}", render_principal_v1()),
        "authority-v1" => print!("{}", render_authority_v1()),
        "apl-v1" => print!("{}", render_apl_v1()),
        "apl-truth-table" => print!("{}", render_apl_truth_table()),
        "object-transition-v1" => print!("{}", render_object_transition_v1()),
        "object-model-table" => print!("{}", render_object_model_table()),
        "state-tree-v1" => print!("{}", render_state_tree_v1()),
        "state-tree-model-table" => print!("{}", render_state_tree_model_table()),
        "object-vm-v1" => print!("{}", render_object_vm_v1()),
        "object-vm-model-table" => print!("{}", render_object_vm_model_table()),
        "devnet-block-v1" => print!("{}", render_devnet_block_v1()),
        "nonce-model-table" => print!("{}", render_nonce_model_table()),
        "epoch-upgrade-model-table" => print!("{}", render_epoch_upgrade_model_table()),
        "codec-length-table" => print!("{}", render_codec_length_table()),
        "credential-v1" => print!("{}", render_credential_v1()),
        "credential-status-table" => print!("{}", render_credential_status_table()),
        "privacy-v1" => print!("{}", render_privacy_v1()),
        "envelope-manifest-v1" => print!("{}", render_envelope_manifest_v1()),
        unknown => {
            eprintln!(
                "unknown vector {unknown}; expected principal-v1, authority-v1, apl-v1, or \
                 apl-truth-table, object-transition-v1, object-model-table, state-tree-v1, or \
                 state-tree-model-table, object-vm-v1, object-vm-model-table, devnet-block-v1, or \
                 nonce-model-table, epoch-upgrade-model-table, codec-length-table, credential-v1, \
                 credential-status-table, privacy-v1, or envelope-manifest-v1"
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use activechain_canonical_codec::{DecodeError, inspect_canonical_envelope};

    use super::{
        render_apl_truth_table, render_apl_v1, render_authority_v1, render_codec_length_table,
        render_credential_status_table, render_credential_v1, render_devnet_block_v1,
        render_envelope_manifest_v1, render_epoch_upgrade_model_table, render_nonce_model_table,
        render_object_model_table, render_object_transition_v1, render_object_vm_model_table,
        render_object_vm_v1, render_principal_v1, render_privacy_v1, render_state_tree_model_table,
        render_state_tree_v1,
    };

    #[test]
    fn generated_principal_vector_is_frozen() {
        let published = include_str!("../../../testing/vectors/canonical/principal-v1.txt");
        assert_eq!(render_principal_v1(), published);
    }

    #[test]
    fn generated_authority_vector_is_frozen() {
        let published = include_str!("../../../testing/vectors/authority/authority-v1.txt");
        assert_eq!(render_authority_v1(), published);
    }

    #[test]
    fn generated_apl_vector_is_frozen() {
        let published = include_str!("../../../testing/vectors/policy/apl-v1.txt");
        assert_eq!(render_apl_v1(), published);
    }

    #[test]
    fn rust_effect_table_matches_the_frozen_lean_table() {
        let published = include_str!("../../../testing/vectors/policy/apl-truth-table.txt");
        assert_eq!(render_apl_truth_table(), published);
    }

    #[test]
    fn generated_object_transition_vector_is_frozen() {
        let published = include_str!("../../../testing/vectors/object/object-transition-v1.txt");
        assert_eq!(render_object_transition_v1(), published);
    }

    #[test]
    fn rust_object_table_matches_the_frozen_lean_table() {
        let published = include_str!("../../../testing/vectors/object/object-model-table.txt");
        assert_eq!(render_object_model_table(), published);
    }

    #[test]
    fn generated_state_tree_vector_is_frozen() {
        let published = include_str!("../../../testing/vectors/state/state-tree-v1.txt");
        assert_eq!(render_state_tree_v1(), published);
    }

    #[test]
    fn rust_state_tree_table_matches_the_frozen_lean_table() {
        let published = include_str!("../../../testing/vectors/state/state-tree-model-table.txt");
        assert_eq!(render_state_tree_model_table(), published);
    }

    #[test]
    fn generated_object_vm_vector_is_frozen() {
        let published = include_str!("../../../testing/vectors/vm/object-vm-v1.txt");
        assert_eq!(render_object_vm_v1(), published);
    }

    #[test]
    fn rust_object_vm_table_matches_the_frozen_lean_table() {
        let published = include_str!("../../../testing/vectors/vm/object-vm-model-table.txt");
        assert_eq!(render_object_vm_model_table(), published);
    }

    #[test]
    fn generated_devnet_block_vector_is_frozen() {
        let published = include_str!("../../../testing/vectors/devnet/devnet-block-v1.txt");
        assert_eq!(render_devnet_block_v1(), published);
    }

    #[test]
    fn rust_nonce_table_matches_the_frozen_lean_table() {
        let published = include_str!("../../../testing/vectors/devnet/nonce-model-table.txt");
        assert_eq!(render_nonce_model_table(), published);
    }

    #[test]
    fn rust_epoch_upgrade_table_matches_the_frozen_lean_table() {
        let published =
            include_str!("../../../testing/vectors/consensus/epoch-upgrade-model-table.txt");
        assert_eq!(render_epoch_upgrade_model_table(), published);
    }

    #[test]
    fn rust_codec_length_table_matches_the_frozen_lean_table() {
        let published = include_str!("../../../testing/vectors/canonical/length-prefix-table.txt");
        assert_eq!(render_codec_length_table(), published);
    }

    #[test]
    fn generated_credential_vector_is_frozen() {
        let published = include_str!("../../../testing/vectors/credential/credential-v1.txt");
        assert_eq!(render_credential_v1(), published);
    }

    #[test]
    fn rust_credential_status_table_matches_the_frozen_lean_table() {
        let published =
            include_str!("../../../testing/vectors/credential/credential-status-table.txt");
        assert_eq!(render_credential_status_table(), published);
    }

    #[test]
    fn generated_privacy_vector_is_frozen() {
        let published = include_str!("../../../testing/vectors/privacy/privacy-v1.txt");
        assert_eq!(render_privacy_v1(), published);
    }

    #[test]
    fn complete_envelope_hash_manifest_is_frozen() {
        let published = include_str!("../../../testing/vectors/envelope-manifest-v1.json");
        let generated = render_envelope_manifest_v1();
        assert_eq!(generated, published);
        assert_eq!(
            generated.matches("\"envelope_sha256\"").count(),
            39,
            "every published envelope must be enumerated exactly once"
        );
    }

    fn vector_files(directory: &Path, output: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).expect("vector directory is readable") {
            let path = entry.expect("vector entry is readable").path();
            if path.is_dir() {
                vector_files(&path, output);
            } else if path.extension().is_some_and(|extension| extension == "txt") {
                output.push(path);
            }
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2), "hex length is even");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => panic!("invalid vector hex digit"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn every_published_envelope_has_strict_canonical_framing() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors");
        let mut files = Vec::new();
        vector_files(&root, &mut files);
        files.sort();
        let mut checked = 0_usize;

        for path in files {
            let text = fs::read_to_string(&path).expect("text vector is UTF-8");
            let fields: BTreeMap<_, _> = text
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.trim(), value.trim()))
                .collect();
            for (key, value) in &fields {
                let Some(prefix) = key.strip_suffix("envelope_hex") else {
                    continue;
                };
                let metadata_prefix = prefix.strip_suffix('_').unwrap_or(prefix);
                let field = |suffix: &str| {
                    if metadata_prefix.is_empty() {
                        suffix.to_owned()
                    } else {
                        format!("{metadata_prefix}_{suffix}")
                    }
                };
                let type_tag =
                    u16::from_str_radix(fields[&*field("type_tag")].trim_start_matches("0x"), 16)
                        .expect("published type tag is u16 hex");
                let schema_version: u16 = fields[&*field("schema_version")]
                    .parse()
                    .expect("published schema version is u16");
                let body_length: usize =
                    fields[&*field("body_length")].parse().expect("published body length is usize");
                let envelope = decode_hex(value);
                let parsed =
                    inspect_canonical_envelope(&envelope, type_tag, schema_version, body_length)
                        .unwrap_or_else(|error| panic!("{} {key}: {error:?}", path.display()));
                assert_eq!(parsed.body().len(), body_length, "{} {key}", path.display());

                let truncated = &envelope[..envelope.len() - 1];
                assert!(
                    inspect_canonical_envelope(truncated, type_tag, schema_version, body_length)
                        .is_err(),
                    "{} {key} truncation",
                    path.display()
                );
                let mut trailing = envelope.clone();
                trailing.push(0);
                assert!(matches!(
                    inspect_canonical_envelope(&trailing, type_tag, schema_version, body_length),
                    Err(DecodeError::TrailingData { remaining: 1 })
                ));

                let prefix_length = envelope.len() - 4 - body_length;
                if prefix_length < 5 {
                    let mut non_minimal = envelope[..4 + prefix_length].to_vec();
                    *non_minimal.last_mut().expect("length prefix exists") |= 0x80;
                    non_minimal.push(0);
                    non_minimal.extend_from_slice(parsed.body());
                    assert_eq!(
                        inspect_canonical_envelope(
                            &non_minimal,
                            type_tag,
                            schema_version,
                            body_length
                        ),
                        Err(DecodeError::NonMinimalLength),
                        "{} {key} redundant prefix",
                        path.display()
                    );
                }
                checked += 1;
            }
        }
        assert!(checked >= 30, "expected the complete published envelope corpus");
    }
}
