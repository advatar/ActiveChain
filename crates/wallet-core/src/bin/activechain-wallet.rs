use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_cash_kernel::VerifierRole;
use activechain_cash_kernel::{
    ChallengeCommitmentV1, CoinTransfer, RewardReplayWitness, challenge_commitment,
};
use activechain_crypto_provider::MlKem768Recipient;
use activechain_protocol_types::{
    AuthenticatorDescriptor, AuthenticatorId, AuthenticatorPurpose, ChainId, CoinCellId,
    CryptoSuiteId, DidControllerOperationV1, DidControllerRecordV1, DidDocumentV1,
    DidKeyAgreementMethodV1, DidOperationAuthorizationV1, DidOperationKind, Digest384,
    ML_KEM_768_PUBLIC_KEY_LENGTH, PrincipalId, ProtocolSignature, derive_activechain_did,
};
use activechain_wallet_core::{
    AuthorizedCashSessionGrantV1, AuthorizedCashTransferV1, AuthorizedDutyReceiptV1,
    AuthorizedVerifierBondRegistrationV1, CashAuthorizationRequestV1, CashSessionGrantV1,
    DutyReceiptV1, VerifierBondRegistrationV1,
};
use activechain_wallet_core::{
    KEYSTORE_MIN_ITERATIONS, KEYSTORE_SALT_LENGTH, is_keystore, open_seed, seal_seed,
};
use ml_dsa::{Keypair, MlDsa44, MlDsa65, Seed, Signer, SigningKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{env, io::Write as _, path::Path};
use zeroize::Zeroize as _;

const KEY_FILE_MAGIC: &[u8; 8] = b"ACWKEY01";
const USAGE: &str = "usage: activechain-wallet <command>\n\
  derive <new-key-file>\n\
  grant-session <key-file> <chain-id> <session-id> <valid-from> <expires-at> <max-spend>\n\
  transfer <key-file> <chain-id> <recipient> <input-cell> <fee-reserve> <nonce> <session-id> \
<session-expires-at> <amount> <fee> <valid-until>\n\
  challenge-commit <challenge-id> <duty> <challenger> <bond-cell> <reward> <evidence> <nonce> \
<reveal-deadline> <resolution-deadline>\n\
  duty-receipt <key-file> <chain-id> <assignment> <evidence> <height>\n\
  bond <key-file> <chain-id> <role> <bond-cell> <bond-amount> <valid-until>\n\
  protect <plain-key-file> <keystore-file>\n\
  redeem-witness <witness-hex-file> <settlement>\n\
  kem-public <key-file>\n\
  did-create <key-file> <chain-genesis> <kem-public-key-hex-file> <valid-from>\n\
  did-rotate <old-key-file> <new-key-file> <chain-genesis> <kem-public-key-hex-file> \
<previous-commitment> <sequence> <valid-from>\n\
  did-recover <recovery-key-file> <new-key-file> <chain-genesis> <kem-public-key-hex-file> \
<previous-commitment> <sequence> <valid-from>\n\
protected keystores read the passphrase from ACTIVECHAIN_WALLET_PASSPHRASE";

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [TABLE[(byte >> 4) as usize] as char, TABLE[(byte & 0x0f) as usize] as char]
        })
        .collect()
}

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err("hex input must have even length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(text.get(i..i + 2).ok_or("hex input is not ASCII")?, 16)
                .map_err(|_| "hex input contains a non-hex character".into())
        })
        .collect()
}

fn parse_digest(text: &str) -> Result<Digest384, String> {
    let bytes = parse_hex(text)?;
    let bytes: [u8; 48] =
        bytes.try_into().map_err(|_| "identifier must be exactly 48 hex-encoded bytes")?;
    Ok(Digest384::new(bytes))
}

fn passphrase() -> Result<Vec<u8>, String> {
    let value = env::var("ACTIVECHAIN_WALLET_PASSPHRASE")
        .map_err(|_| "set ACTIVECHAIN_WALLET_PASSPHRASE to open a protected keystore")?;
    if value.is_empty() {
        return Err("the keystore passphrase must not be empty".into());
    }
    Ok(value.into_bytes())
}

fn plain_seed(bytes: &[u8]) -> Result<[u8; 32], String> {
    let (magic, seed) =
        bytes.split_at_checked(KEY_FILE_MAGIC.len()).ok_or("key file is truncated")?;
    if magic != KEY_FILE_MAGIC {
        return Err("key file has an unknown format".into());
    }
    seed.try_into().map_err(|_| "key file seed must be exactly 32 bytes".into())
}

fn load_seed(path: &str) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(Path::new(path)).map_err(|error| format!("{path}: {error}"))?;
    if is_keystore(&bytes) {
        let mut secret = passphrase()?;
        let seed = open_seed(&bytes, &secret)
            .map_err(|_| "keystore rejected: wrong passphrase or tampered file")?;
        secret.zeroize();
        Ok(seed)
    } else {
        plain_seed(&bytes)
    }
}

fn load_signing_key(path: &str) -> Result<SigningKey<MlDsa44>, String> {
    let mut seed = load_seed(path)?;
    let key = SigningKey::<MlDsa44>::from_seed(&Seed::from(seed));
    seed.zeroize();
    Ok(key)
}

/// Loads the wallet principal (over the ML-DSA-44 key, exactly as `derive` prints it) together
/// with the ML-DSA-65 DID control key derived from the same seed. DID Control and Recovery
/// authenticators require ML-DSA-65 or stronger, so the wallet's ML-DSA-44 key cannot appear in a
/// DID document directly.
fn load_did_control_key(path: &str) -> Result<(PrincipalId, SigningKey<MlDsa65>), String> {
    let mut seed = load_seed(path)?;
    let principal = principal_for(&SigningKey::<MlDsa44>::from_seed(&Seed::from(seed)));
    let key = SigningKey::<MlDsa65>::from_seed(&Seed::from(seed));
    seed.zeroize();
    Ok((principal, key))
}

/// Expands the 32-byte wallet seed into the 64-byte ML-KEM-768 derivation seed through a
/// domain-separated SHAKE256 read, so the KEM key never reuses the signing-seed bytes directly.
fn kem_seed(seed: &[u8; 32]) -> [u8; 64] {
    let mut shake = Shake256::default();
    shake.update(b"ACTIVECHAIN-WALLET-KEM-SEED-V1");
    shake.update(seed);
    let mut expanded = [0_u8; 64];
    shake.finalize_xof().read(&mut expanded);
    expanded
}

fn shake384(domain: &[u8], parts: &[&[u8]]) -> Digest384 {
    let mut shake = Shake256::default();
    shake.update(domain);
    for part in parts {
        shake.update(part);
    }
    let mut digest = [0_u8; 48];
    shake.finalize_xof().read(&mut digest);
    Digest384::new(digest)
}

fn principal_for(key: &SigningKey<MlDsa44>) -> PrincipalId {
    let public_key = key.verifying_key().encode();
    PrincipalId::new(shake384(b"ACTIVECHAIN-WALLET-PUBLIC-KEY-ID-V1", &[public_key.as_slice()]))
}

fn sign(key: &SigningKey<MlDsa44>, payload: &[u8]) -> Result<ProtocolSignature, String> {
    ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, key.sign(payload).encode().as_slice().to_vec())
        .map_err(|_| "signature construction failed".into())
}

fn build_session_grant(
    key: &SigningKey<MlDsa44>,
    chain_id: ChainId,
    session_id: Digest384,
    valid_from: u64,
    expires_at: u64,
    max_spend: u128,
) -> Result<AuthorizedCashSessionGrantV1, String> {
    let grant = CashSessionGrantV1::new(
        chain_id,
        principal_for(key),
        session_id,
        valid_from,
        expires_at,
        max_spend,
    )
    .map_err(|error| format!("invalid session grant: {error:?}"))?;
    let payload = grant.signing_payload().map_err(|_| "grant encoding failed")?;
    AuthorizedCashSessionGrantV1::new(grant, sign(key, &payload)?)
        .map_err(|error| format!("grant authorization failed: {error:?}"))
}

#[allow(clippy::too_many_arguments)]
fn build_transfer(
    key: &SigningKey<MlDsa44>,
    chain_id: ChainId,
    recipient: PrincipalId,
    input: CoinCellId,
    fee_reserve: CoinCellId,
    nonce: u64,
    session_id: Digest384,
    session_expires_at: u64,
    amount: u128,
    fee: u128,
    valid_until: u64,
) -> Result<(AuthorizedCashTransferV1, Digest384), String> {
    let signer = principal_for(key);
    let transfer =
        CoinTransfer::new(signer, recipient, vec![input], fee_reserve, amount, fee, valid_until)
            .map_err(|error| format!("invalid transfer: {error:?}"))?;
    let request = CashAuthorizationRequestV1::new(
        chain_id,
        signer,
        nonce,
        session_id,
        session_expires_at,
        transfer,
    )
    .map_err(|error| format!("invalid authorization request: {error:?}"))?;
    let intent = request.intent_id().map_err(|_| "intent derivation failed")?;
    let payload = request.signing_payload().map_err(|_| "request encoding failed")?;
    let authorized = AuthorizedCashTransferV1::new(request, sign(key, &payload)?)
        .map_err(|error| format!("transfer authorization failed: {error:?}"))?;
    Ok((authorized, intent))
}

#[allow(clippy::too_many_arguments)]
fn build_challenge_commitment(
    challenge_id: Digest384,
    duty: Digest384,
    challenger: PrincipalId,
    bond: CoinCellId,
    reward: u128,
    evidence: Digest384,
    nonce: Digest384,
    reveal_deadline: u64,
    resolution_deadline: u64,
) -> Result<ChallengeCommitmentV1, String> {
    if evidence == Digest384::ZERO || nonce == Digest384::ZERO {
        return Err("challenge evidence and nonce must be non-zero".into());
    }
    let commitment = challenge_commitment(challenge_id, duty, challenger, evidence, nonce);
    ChallengeCommitmentV1::new(
        challenge_id,
        duty,
        challenger,
        bond,
        reward,
        commitment,
        reveal_deadline,
        resolution_deadline,
    )
    .map_err(|error| format!("invalid challenge commitment: {error:?}"))
}

fn parse_role(text: &str) -> Result<VerifierRole, String> {
    match text {
        "finality" => Ok(VerifierRole::Finality),
        "availability" => Ok(VerifierRole::Availability),
        "audit" => Ok(VerifierRole::Audit),
        "assurance" => Ok(VerifierRole::Assurance),
        "public-goods" => Ok(VerifierRole::PublicGoods),
        _ => Err("role must be finality, availability, audit, assurance, or public-goods".into()),
    }
}

fn build_bond_registration(
    key: &SigningKey<MlDsa44>,
    chain_id: ChainId,
    role: VerifierRole,
    bond: CoinCellId,
    bond_amount: u128,
    valid_until: u64,
) -> Result<AuthorizedVerifierBondRegistrationV1, String> {
    let registration = VerifierBondRegistrationV1::new(
        chain_id,
        principal_for(key),
        role,
        bond,
        bond_amount,
        valid_until,
    )
    .map_err(|error| format!("invalid bond registration: {error:?}"))?;
    let payload = registration.signing_payload().map_err(|_| "registration encoding failed")?;
    AuthorizedVerifierBondRegistrationV1::new(registration, sign(key, &payload)?)
        .map_err(|error| format!("bond authorization failed: {error:?}"))
}

fn build_duty_receipt(
    key: &SigningKey<MlDsa44>,
    chain_id: ChainId,
    assignment: Digest384,
    evidence: Digest384,
    height: u64,
) -> Result<AuthorizedDutyReceiptV1, String> {
    let receipt = DutyReceiptV1::new(chain_id, assignment, principal_for(key), evidence, height)
        .map_err(|error| format!("invalid duty receipt: {error:?}"))?;
    let payload = receipt.signing_payload().map_err(|_| "receipt encoding failed")?;
    AuthorizedDutyReceiptV1::new(receipt, sign(key, &payload)?)
        .map_err(|error| format!("receipt authorization failed: {error:?}"))
}

fn validate_reward_witness(
    envelope: &[u8],
    settlement: Digest384,
) -> Result<RewardReplayWitness, String> {
    let witness: RewardReplayWitness =
        decode_envelope(envelope).map_err(|_| "malformed reward replay witness envelope")?;
    if witness.assignment() != settlement {
        return Err("witness is bound to a different settlement assignment".into());
    }
    Ok(witness)
}

fn did_verifying_key(key: &SigningKey<MlDsa65>) -> Vec<u8> {
    key.verifying_key().encode().as_slice().to_vec()
}

fn did_authenticator_id(public_key: &[u8]) -> AuthenticatorId {
    AuthenticatorId::new(shake384(b"ACTIVECHAIN-WALLET-DID-AUTHENTICATOR-ID-V1", &[public_key]))
}

fn did_agreement_method_id(public_key: &[u8]) -> AuthenticatorId {
    AuthenticatorId::new(shake384(b"ACTIVECHAIN-WALLET-DID-KEY-AGREEMENT-ID-V1", &[public_key]))
}

/// Commits the operation to its exact authorizer identity and verifying key. The canonical types
/// only require this commitment to be non-zero; verifiers check the signed network-bound
/// authorization envelope, not this preimage.
fn did_authorization_commitment(authorizer: AuthenticatorId, public_key: &[u8]) -> Digest384 {
    shake384(
        b"ACTIVECHAIN-WALLET-DID-OPERATION-AUTHORIZER-V1",
        &[authorizer.digest().as_bytes(), public_key],
    )
}

fn build_did_document(
    principal: PrincipalId,
    control_public_key: Vec<u8>,
    kem_public_key: Vec<u8>,
    valid_from: u64,
) -> Result<DidDocumentV1, String> {
    if kem_public_key.len() != ML_KEM_768_PUBLIC_KEY_LENGTH {
        return Err(format!(
            "ML-KEM-768 public key must be exactly {ML_KEM_768_PUBLIC_KEY_LENGTH} bytes"
        ));
    }
    let control = AuthenticatorDescriptor::new(
        did_authenticator_id(&control_public_key),
        CryptoSuiteId::ML_DSA_65,
        control_public_key,
        AuthenticatorPurpose::Control,
        valid_from,
        None,
        None,
    )
    .map_err(|error| format!("invalid control authenticator: {error:?}"))?;
    let agreement = DidKeyAgreementMethodV1::new(
        did_agreement_method_id(&kem_public_key),
        CryptoSuiteId::ML_KEM_768,
        kem_public_key,
        valid_from,
        None,
        None,
    )
    .map_err(|error| format!("invalid key-agreement method: {error:?}"))?;
    DidDocumentV1::new(principal, vec![control], vec![agreement], None)
        .map_err(|error| format!("invalid DID document: {error:?}"))
}

fn sign_did_authorization(
    chain_genesis: Digest384,
    operation: &DidControllerOperationV1,
    signer: &SigningKey<MlDsa65>,
) -> Result<DidOperationAuthorizationV1, String> {
    let authorizer = did_authenticator_id(&did_verifying_key(signer));
    let placeholder_length =
        CryptoSuiteId::ML_DSA_65.signature_length().ok_or("suite does not sign")?;
    let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_65, vec![0; placeholder_length])
        .map_err(|_| "signature construction failed")?;
    let unsigned =
        DidOperationAuthorizationV1::new(chain_genesis, operation, authorizer, placeholder)
            .map_err(|error| format!("authorization construction failed: {error:?}"))?;
    let signature = ProtocolSignature::new(
        CryptoSuiteId::ML_DSA_65,
        signer.sign(&unsigned.signing_payload()).encode().as_slice().to_vec(),
    )
    .map_err(|_| "signature construction failed")?;
    DidOperationAuthorizationV1::new(chain_genesis, operation, authorizer, signature)
        .map_err(|error| format!("authorization construction failed: {error:?}"))
}

fn build_did_create(
    principal: PrincipalId,
    control_key: &SigningKey<MlDsa65>,
    chain_genesis: Digest384,
    kem_public_key: Vec<u8>,
    valid_from: u64,
) -> Result<(DidDocumentV1, DidControllerOperationV1, DidOperationAuthorizationV1), String> {
    let public_key = did_verifying_key(control_key);
    let document = build_did_document(principal, public_key.clone(), kem_public_key, valid_from)?;
    let record = DidControllerRecordV1::from_document(&document, 1, true)
        .map_err(|error| format!("invalid controller record: {error:?}"))?;
    let authorizer = did_authenticator_id(&public_key);
    let operation = DidControllerOperationV1::new(
        DidOperationKind::Create,
        principal,
        None,
        record,
        did_authorization_commitment(authorizer, &public_key),
    )
    .map_err(|error| format!("invalid DID operation: {error:?}"))?;
    let authorization = sign_did_authorization(chain_genesis, &operation, control_key)?;
    Ok((document, operation, authorization))
}

#[allow(clippy::too_many_arguments)]
fn build_did_transition(
    kind: DidOperationKind,
    principal: PrincipalId,
    signer: &SigningKey<MlDsa65>,
    new_control_key: &SigningKey<MlDsa65>,
    chain_genesis: Digest384,
    kem_public_key: Vec<u8>,
    previous_commitment: Digest384,
    sequence: u64,
    valid_from: u64,
) -> Result<(DidDocumentV1, DidControllerOperationV1, DidOperationAuthorizationV1), String> {
    if sequence <= 1 {
        return Err("sequence must be greater than 1 for update and recover operations".into());
    }
    if previous_commitment == Digest384::ZERO {
        return Err("previous commitment must be non-zero".into());
    }
    let signer_public_key = did_verifying_key(signer);
    let document = build_did_document(
        principal,
        did_verifying_key(new_control_key),
        kem_public_key,
        valid_from,
    )?;
    let record = DidControllerRecordV1::from_document(&document, sequence, true)
        .map_err(|error| format!("invalid controller record: {error:?}"))?;
    let authorizer = did_authenticator_id(&signer_public_key);
    let operation = DidControllerOperationV1::new(
        kind,
        principal,
        Some(previous_commitment),
        record,
        did_authorization_commitment(authorizer, &signer_public_key),
    )
    .map_err(|error| format!("invalid DID operation: {error:?}"))?;
    let authorization = sign_did_authorization(chain_genesis, &operation, signer)?;
    Ok((document, operation, authorization))
}

fn print_did_operation(
    principal: PrincipalId,
    operation: &DidControllerOperationV1,
    authorization: &DidOperationAuthorizationV1,
) -> Result<(), String> {
    let did = derive_activechain_did(principal)
        .map_err(|error| format!("invalid principal: {error:?}"))?;
    println!("did={}", hex(did.as_bytes()));
    println!(
        "operation={}",
        hex(&encode_envelope(operation).map_err(|_| "envelope encoding failed")?)
    );
    println!(
        "authorization={}",
        hex(&encode_envelope(authorization).map_err(|_| "envelope encoding failed")?)
    );
    Ok(())
}

fn read_kem_public_key(path: &str) -> Result<Vec<u8>, String> {
    let text =
        std::fs::read_to_string(Path::new(path)).map_err(|error| format!("{path}: {error}"))?;
    parse_hex(&text)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or(USAGE)?;
    let arguments: Vec<String> = args.collect();
    match command.as_str() {
        "derive" => {
            let [key_file] = arguments.as_slice() else {
                return Err(USAGE.into());
            };
            let mut seed = [0_u8; 32];
            getrandom::fill(&mut seed).map_err(|_| "operating-system randomness unavailable")?;
            let key = SigningKey::<MlDsa44>::from_seed(&Seed::from(seed));
            #[cfg(unix)]
            let mut file = {
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(Path::new(key_file))?
            };
            #[cfg(not(unix))]
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(Path::new(key_file))?;
            file.write_all(KEY_FILE_MAGIC)?;
            file.write_all(&seed)?;
            file.sync_all()?;
            seed.zeroize();
            println!("suite=ML_DSA_44");
            println!("principal_id={}", hex(principal_for(&key).into_digest().as_bytes()));
            println!("public_key={}", hex(key.verifying_key().encode().as_slice()));
            println!("key_file={key_file}");
        }
        "grant-session" => {
            let [key_file, chain_id, session_id, valid_from, expires_at, max_spend] =
                arguments.as_slice()
            else {
                return Err(USAGE.into());
            };
            let key = load_signing_key(key_file)?;
            let authorized = build_session_grant(
                &key,
                ChainId::new(parse_digest(chain_id)?),
                parse_digest(session_id)?,
                valid_from.parse()?,
                expires_at.parse()?,
                max_spend.parse()?,
            )?;
            println!("signer={}", hex(principal_for(&key).into_digest().as_bytes()));
            println!(
                "authorized_session={}",
                hex(&encode_envelope(&authorized).map_err(|_| "envelope encoding failed")?)
            );
        }
        "transfer" => {
            let [
                key_file,
                chain_id,
                recipient,
                input,
                fee_reserve,
                nonce,
                session_id,
                session_expires_at,
                amount,
                fee,
                valid_until,
            ] = arguments.as_slice()
            else {
                return Err(USAGE.into());
            };
            let key = load_signing_key(key_file)?;
            let (authorized, intent) = build_transfer(
                &key,
                ChainId::new(parse_digest(chain_id)?),
                PrincipalId::new(parse_digest(recipient)?),
                CoinCellId::new(parse_digest(input)?),
                CoinCellId::new(parse_digest(fee_reserve)?),
                nonce.parse()?,
                parse_digest(session_id)?,
                session_expires_at.parse()?,
                amount.parse()?,
                fee.parse()?,
                valid_until.parse()?,
            )?;
            println!("signer={}", hex(principal_for(&key).into_digest().as_bytes()));
            println!("intent_id={}", hex(intent.as_bytes()));
            println!(
                "authorized_transfer={}",
                hex(&encode_envelope(&authorized).map_err(|_| "envelope encoding failed")?)
            );
        }
        "challenge-commit" => {
            let [
                challenge_id,
                duty,
                challenger,
                bond,
                reward,
                evidence,
                nonce,
                reveal_deadline,
                resolution_deadline,
            ] = arguments.as_slice()
            else {
                return Err(USAGE.into());
            };
            let commitment = build_challenge_commitment(
                parse_digest(challenge_id)?,
                parse_digest(duty)?,
                PrincipalId::new(parse_digest(challenger)?),
                CoinCellId::new(parse_digest(bond)?),
                reward.parse()?,
                parse_digest(evidence)?,
                parse_digest(nonce)?,
                reveal_deadline.parse()?,
                resolution_deadline.parse()?,
            )?;
            println!(
                "challenge_commitment={}",
                hex(&encode_envelope(&commitment).map_err(|_| "envelope encoding failed")?)
            );
            println!("keep evidence and nonce private until the reveal step");
        }
        "duty-receipt" => {
            let [key_file, chain_id, assignment, evidence, height] = arguments.as_slice() else {
                return Err(USAGE.into());
            };
            let key = load_signing_key(key_file)?;
            let authorized = build_duty_receipt(
                &key,
                ChainId::new(parse_digest(chain_id)?),
                parse_digest(assignment)?,
                parse_digest(evidence)?,
                height.parse()?,
            )?;
            println!("verifier={}", hex(principal_for(&key).into_digest().as_bytes()));
            println!(
                "authorized_duty_receipt={}",
                hex(&encode_envelope(&authorized).map_err(|_| "envelope encoding failed")?)
            );
        }
        "bond" => {
            let [key_file, chain_id, role, bond, bond_amount, valid_until] = arguments.as_slice()
            else {
                return Err(USAGE.into());
            };
            let key = load_signing_key(key_file)?;
            let authorized = build_bond_registration(
                &key,
                ChainId::new(parse_digest(chain_id)?),
                parse_role(role)?,
                CoinCellId::new(parse_digest(bond)?),
                bond_amount.parse()?,
                valid_until.parse()?,
            )?;
            println!("verifier={}", hex(principal_for(&key).into_digest().as_bytes()));
            println!(
                "authorized_bond_registration={}",
                hex(&encode_envelope(&authorized).map_err(|_| "envelope encoding failed")?)
            );
        }
        "protect" => {
            let [plain_file, keystore_file] = arguments.as_slice() else {
                return Err(USAGE.into());
            };
            let bytes = std::fs::read(Path::new(plain_file))
                .map_err(|error| format!("{plain_file}: {error}"))?;
            let mut seed = plain_seed(&bytes)?;
            let mut secret = passphrase()?;
            let mut salt = [0_u8; KEYSTORE_SALT_LENGTH];
            getrandom::fill(&mut salt).map_err(|_| "operating-system randomness unavailable")?;
            let sealed = seal_seed(&seed, &secret, salt, KEYSTORE_MIN_ITERATIONS)
                .map_err(|error| format!("keystore sealing failed: {error:?}"))?;
            seed.zeroize();
            secret.zeroize();
            #[cfg(unix)]
            let mut file = {
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(Path::new(keystore_file))?
            };
            #[cfg(not(unix))]
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(Path::new(keystore_file))?;
            file.write_all(&sealed)?;
            file.sync_all()?;
            println!("keystore_file={keystore_file}");
            println!("iterations={KEYSTORE_MIN_ITERATIONS}");
        }
        "redeem-witness" => {
            let [witness_file, settlement] = arguments.as_slice() else {
                return Err(USAGE.into());
            };
            let text = std::fs::read_to_string(Path::new(witness_file))
                .map_err(|error| format!("{witness_file}: {error}"))?;
            let witness = validate_reward_witness(&parse_hex(&text)?, parse_digest(settlement)?)?;
            println!("assignment={}", hex(witness.assignment().as_bytes()));
            println!("siblings={}", witness.siblings().len());
            println!("witness=valid");
        }
        "kem-public" => {
            let [key_file] = arguments.as_slice() else {
                return Err(USAGE.into());
            };
            let mut seed = load_seed(key_file)?;
            let mut expanded = kem_seed(&seed);
            seed.zeroize();
            let recipient = MlKem768Recipient::from_seed(expanded);
            expanded.zeroize();
            println!("suite=ML_KEM_768");
            println!("kem_public_key={}", hex(&recipient.public_key()));
        }
        "did-create" => {
            let [key_file, chain_genesis, kem_file, valid_from] = arguments.as_slice() else {
                return Err(USAGE.into());
            };
            let (principal, control_key) = load_did_control_key(key_file)?;
            let (_, operation, authorization) = build_did_create(
                principal,
                &control_key,
                parse_digest(chain_genesis)?,
                read_kem_public_key(kem_file)?,
                valid_from.parse()?,
            )?;
            print_did_operation(principal, &operation, &authorization)?;
        }
        "did-rotate" | "did-recover" => {
            let [
                signer_key_file,
                new_key_file,
                chain_genesis,
                kem_file,
                previous_commitment,
                sequence,
                valid_from,
            ] = arguments.as_slice()
            else {
                return Err(USAGE.into());
            };
            let kind = if command == "did-rotate" {
                DidOperationKind::Update
            } else {
                DidOperationKind::Recover
            };
            let (principal, signer_key) = load_did_control_key(signer_key_file)?;
            let (_, new_key) = load_did_control_key(new_key_file)?;
            let (_, operation, authorization) = build_did_transition(
                kind,
                principal,
                &signer_key,
                &new_key,
                parse_digest(chain_genesis)?,
                read_kem_public_key(kem_file)?,
                parse_digest(previous_commitment)?,
                sequence.parse()?,
                valid_from.parse()?,
            )?;
            print_did_operation(principal, &operation, &authorization)?;
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_accumulator::{AccumulatorDomain, ReferenceSet};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn key() -> SigningKey<MlDsa44> {
        SigningKey::<MlDsa44>::from_seed(&Seed::from([7; 32]))
    }

    #[test]
    fn hex_round_trips_and_rejects_malformed_input() {
        assert_eq!(parse_hex(&hex(&[0, 15, 255])).unwrap(), vec![0, 15, 255]);
        assert!(parse_hex("abc").is_err());
        assert!(parse_hex("zz").is_err());
        assert!(parse_digest("ffff").is_err());
    }

    #[test]
    fn session_grant_binds_the_key_principal_and_round_trips() {
        let key = key();
        let authorized =
            build_session_grant(&key, ChainId::new(digest(1)), digest(6), 1, 9, 100).unwrap();
        assert_eq!(authorized.grant().signer(), principal_for(&key));
        let encoded = encode_envelope(&authorized).unwrap();
        assert_eq!(decode_envelope::<AuthorizedCashSessionGrantV1>(&encoded), Ok(authorized));
    }

    #[test]
    fn transfer_signs_a_decodable_envelope_with_a_stable_intent() {
        let key = key();
        let (authorized, intent) = build_transfer(
            &key,
            ChainId::new(digest(1)),
            PrincipalId::new(digest(3)),
            CoinCellId::new(digest(4)),
            CoinCellId::new(digest(5)),
            7,
            digest(6),
            9,
            50,
            2,
            10,
        )
        .unwrap();
        assert_eq!(authorized.request().signer(), principal_for(&key));
        assert_eq!(authorized.request().intent_id(), Ok(intent));
        let encoded = encode_envelope(&authorized).unwrap();
        assert_eq!(decode_envelope::<AuthorizedCashTransferV1>(&encoded), Ok(authorized));
    }

    #[test]
    fn expired_session_windows_fail_closed() {
        let key = key();
        assert!(
            build_transfer(
                &key,
                ChainId::new(digest(1)),
                PrincipalId::new(digest(3)),
                CoinCellId::new(digest(4)),
                CoinCellId::new(digest(5)),
                7,
                digest(6),
                20,
                50,
                2,
                10,
            )
            .is_err()
        );
    }

    #[test]
    fn challenge_commitment_matches_the_reveal_preimage() {
        let commitment = build_challenge_commitment(
            digest(1),
            digest(2),
            PrincipalId::new(digest(3)),
            CoinCellId::new(digest(4)),
            9,
            digest(5),
            digest(6),
            10,
            20,
        )
        .unwrap();
        assert!(commitment.reveal(digest(5), digest(6), 10).is_ok());
        assert!(
            build_challenge_commitment(
                digest(1),
                digest(2),
                PrincipalId::new(digest(3)),
                CoinCellId::new(digest(4)),
                9,
                Digest384::ZERO,
                digest(6),
                10,
                20,
            )
            .is_err()
        );
    }

    #[test]
    fn duty_receipt_verifies_only_for_the_signing_verifier_and_exact_chain() {
        let key = key();
        let authorized =
            build_duty_receipt(&key, ChainId::new(digest(1)), digest(2), digest(3), 9).unwrap();
        let public_key = key.verifying_key().encode();
        let verifier = principal_for(&key);
        assert_eq!(
            authorized.verify(public_key.as_slice(), ChainId::new(digest(1)), verifier),
            Ok(())
        );
        assert!(
            authorized.verify(public_key.as_slice(), ChainId::new(digest(9)), verifier).is_err()
        );
        assert!(
            authorized
                .verify(
                    public_key.as_slice(),
                    ChainId::new(digest(1)),
                    PrincipalId::new(digest(4)),
                )
                .is_err()
        );
        let encoded = encode_envelope(&authorized).unwrap();
        assert_eq!(decode_envelope::<AuthorizedDutyReceiptV1>(&encoded), Ok(authorized));
        assert!(
            build_duty_receipt(&key, ChainId::new(digest(1)), Digest384::ZERO, digest(3), 9)
                .is_err()
        );
    }

    #[test]
    fn bond_registration_verifies_only_for_the_signing_verifier_and_exact_chain() {
        let key = key();
        let authorized = build_bond_registration(
            &key,
            ChainId::new(digest(1)),
            VerifierRole::Audit,
            CoinCellId::new(digest(2)),
            100,
            9,
        )
        .unwrap();
        let public_key = key.verifying_key().encode();
        let verifier = principal_for(&key);
        assert_eq!(
            authorized.verify(public_key.as_slice(), ChainId::new(digest(1)), verifier),
            Ok(())
        );
        assert!(
            authorized.verify(public_key.as_slice(), ChainId::new(digest(9)), verifier).is_err()
        );
        let encoded = encode_envelope(&authorized).unwrap();
        assert_eq!(
            decode_envelope::<AuthorizedVerifierBondRegistrationV1>(&encoded),
            Ok(authorized)
        );
        assert!(
            build_bond_registration(
                &key,
                ChainId::new(digest(1)),
                VerifierRole::Audit,
                CoinCellId::new(digest(2)),
                0,
                9,
            )
            .is_err()
        );
        assert!(parse_role("finality").is_ok());
        assert!(parse_role("unknown").is_err());
    }

    fn did_key(byte: u8) -> SigningKey<MlDsa65> {
        SigningKey::<MlDsa65>::from_seed(&Seed::from([byte; 32]))
    }

    fn kem_public_key(byte: u8) -> Vec<u8> {
        vec![byte; ML_KEM_768_PUBLIC_KEY_LENGTH]
    }

    #[test]
    fn did_create_round_trips_and_binds_a_verifiable_signature() {
        let control = did_key(7);
        let principal = principal_for(&key());
        let genesis = digest(6);
        let (document, operation, authorization) =
            build_did_create(principal, &control, genesis, kem_public_key(9), 1).unwrap();
        assert_eq!(operation.kind(), DidOperationKind::Create);
        assert_eq!(operation.principal(), principal);
        assert_eq!(operation.next().sequence(), 1);
        assert!(authorization.binds(genesis, &operation));
        let encoded = encode_envelope(&operation).unwrap();
        assert_eq!(decode_envelope::<DidControllerOperationV1>(&encoded), Ok(operation.clone()));
        let encoded = encode_envelope(&authorization).unwrap();
        assert_eq!(
            decode_envelope::<DidOperationAuthorizationV1>(&encoded),
            Ok(authorization.clone())
        );
        let method = document.method(authorization.authorizer()).unwrap();
        assert_eq!(method.purpose(), AuthenticatorPurpose::Control);
        assert_eq!(
            activechain_crypto_provider::verify_did_signature(
                method.scheme(),
                method.verification_key(),
                &authorization.signing_payload(),
                authorization.signature().as_bytes(),
            ),
            Ok(())
        );
    }

    #[test]
    fn did_rotate_is_accepted_by_the_crypto_provider_verifier() {
        let old_control = did_key(7);
        let new_control = did_key(8);
        let principal = principal_for(&key());
        let genesis = digest(6);
        let (current_document, create_operation, _) =
            build_did_create(principal, &old_control, genesis, kem_public_key(9), 1).unwrap();
        let current = *create_operation.next();
        let (next_document, operation, authorization) = build_did_transition(
            DidOperationKind::Update,
            principal,
            &old_control,
            &new_control,
            genesis,
            kem_public_key(10),
            current.commitment().unwrap(),
            2,
            1,
        )
        .unwrap();
        assert_eq!(
            activechain_crypto_provider::verify_did_operation_authorization(
                &current,
                &current_document,
                &operation,
                &next_document,
                &authorization,
                genesis,
                1,
            ),
            Ok(*operation.next())
        );
    }

    #[test]
    fn did_recover_binds_the_recovery_authorizer_and_signature() {
        let recovery = did_key(11);
        let new_control = did_key(12);
        let principal = principal_for(&key());
        let genesis = digest(6);
        let (_, operation, authorization) = build_did_transition(
            DidOperationKind::Recover,
            principal,
            &recovery,
            &new_control,
            genesis,
            kem_public_key(10),
            digest(3),
            2,
            1,
        )
        .unwrap();
        assert_eq!(operation.kind(), DidOperationKind::Recover);
        let recovery_public = did_verifying_key(&recovery);
        assert_eq!(authorization.authorizer(), did_authenticator_id(&recovery_public));
        assert!(authorization.binds(genesis, &operation));
        assert_eq!(
            activechain_crypto_provider::verify_did_signature(
                CryptoSuiteId::ML_DSA_65,
                &recovery_public,
                &authorization.signing_payload(),
                authorization.signature().as_bytes(),
            ),
            Ok(())
        );
    }

    #[test]
    fn did_transitions_reject_bad_sequences_commitments_and_kem_keys() {
        let old_control = did_key(7);
        let new_control = did_key(8);
        let principal = principal_for(&key());
        let genesis = digest(6);
        for sequence in [0, 1] {
            assert!(
                build_did_transition(
                    DidOperationKind::Update,
                    principal,
                    &old_control,
                    &new_control,
                    genesis,
                    kem_public_key(10),
                    digest(3),
                    sequence,
                    1,
                )
                .is_err()
            );
        }
        assert!(
            build_did_transition(
                DidOperationKind::Update,
                principal,
                &old_control,
                &new_control,
                genesis,
                kem_public_key(10),
                Digest384::ZERO,
                2,
                1,
            )
            .is_err()
        );
        assert!(
            build_did_transition(
                DidOperationKind::Update,
                principal,
                &old_control,
                &new_control,
                genesis,
                vec![10; ML_KEM_768_PUBLIC_KEY_LENGTH - 1],
                digest(3),
                2,
                1,
            )
            .is_err()
        );
        assert!(build_did_create(principal, &old_control, genesis, vec![1; 10], 1).is_err());
    }

    #[test]
    fn kem_derivation_is_deterministic_and_seed_bound() {
        let first = MlKem768Recipient::from_seed(kem_seed(&[7; 32])).public_key();
        let second = MlKem768Recipient::from_seed(kem_seed(&[7; 32])).public_key();
        assert_eq!(first, second);
        assert_eq!(first.len(), ML_KEM_768_PUBLIC_KEY_LENGTH);
        let other = MlKem768Recipient::from_seed(kem_seed(&[8; 32])).public_key();
        assert_ne!(first, other);
    }

    #[test]
    fn reward_witness_validation_binds_the_settlement_assignment() {
        let reference = ReferenceSet::new(AccumulatorDomain::SpentInput);
        let assignment = digest(9);
        let witness = reference.non_membership_witness(assignment.into_bytes()).unwrap();
        let witness = RewardReplayWitness::new(
            assignment,
            witness.siblings.into_iter().map(Digest384::new).collect(),
        )
        .unwrap();
        let envelope = encode_envelope(&witness).unwrap();
        assert_eq!(validate_reward_witness(&envelope, assignment), Ok(witness));
        assert!(validate_reward_witness(&envelope, digest(8)).is_err());
        assert!(validate_reward_witness(&[0, 1, 2], assignment).is_err());
    }
}
