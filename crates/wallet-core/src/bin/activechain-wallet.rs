use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_cash_kernel::{
    ChallengeCommitmentV1, CoinTransfer, RewardReplayWitness, challenge_commitment,
};
use activechain_protocol_types::{
    ChainId, CoinCellId, CryptoSuiteId, Digest384, PrincipalId, ProtocolSignature,
};
use activechain_wallet_core::{
    AuthorizedCashSessionGrantV1, AuthorizedCashTransferV1, AuthorizedDutyReceiptV1,
    CashAuthorizationRequestV1, CashSessionGrantV1, DutyReceiptV1,
};
use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
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
  redeem-witness <witness-hex-file> <settlement>";

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

fn load_signing_key(path: &str) -> Result<SigningKey<MlDsa44>, String> {
    let bytes = std::fs::read(Path::new(path)).map_err(|error| format!("{path}: {error}"))?;
    let (magic, seed) =
        bytes.split_at_checked(KEY_FILE_MAGIC.len()).ok_or("key file is truncated")?;
    if magic != KEY_FILE_MAGIC {
        return Err("key file has an unknown format".into());
    }
    let mut seed: [u8; 32] =
        seed.try_into().map_err(|_| "key file seed must be exactly 32 bytes")?;
    let key = SigningKey::<MlDsa44>::from_seed(&Seed::from(seed));
    seed.zeroize();
    Ok(key)
}

fn principal_for(key: &SigningKey<MlDsa44>) -> PrincipalId {
    let public_key = key.verifying_key().encode();
    let mut principal = [0_u8; 48];
    let mut shake = Shake256::default();
    shake.update(b"ACTIVECHAIN-WALLET-PUBLIC-KEY-ID-V1");
    shake.update(public_key.as_slice());
    shake.finalize_xof().read(&mut principal);
    PrincipalId::new(Digest384::new(principal))
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
