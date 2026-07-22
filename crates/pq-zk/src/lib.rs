#![forbid(unsafe_code)]

//! ActiveChain PQ-ZK v1 transparent STARK profile.

use activechain_canonical_codec::{CanonicalType, encode_envelope};
use activechain_pq_zk_methods::{
    ACTIVECHAIN_PQ_ZK_GUEST_ELF as GUEST_ELF, ACTIVECHAIN_PQ_ZK_GUEST_ID as GUEST_ID,
    BILLBOARD_POST_ELF, BILLBOARD_POST_ID, BILLBOARD_WITHDRAW_ELF, BILLBOARD_WITHDRAW_ID,
};
use activechain_private_billboard::{PostRelationInput, WithdrawalRelationInput};
use activechain_protocol_types::Digest384;
use risc0_zkvm::{ExecutorEnv, ProverOpts, Receipt, default_executor, default_prover};
use sha3::{Digest, Sha3_256};

/// Consensus-visible identifier for this exact proof profile.
pub const PROFILE_ID: &str = "ACTIVECHAIN-PQ-ZK-RISC0-STARK-V1";

/// A SHA3-256 commitment to a private byte string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicStatement(pub [u8; 32]);

/// A succinct, transparent zk-STARK receipt from the pinned guest image.
pub struct PqZkProof {
    receipt: Receipt,
}

pub struct BillboardPqZkProof {
    receipt: Receipt,
}

const POST_JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-BILLBOARD-POST-RISC0-STARK-V1";
const WITHDRAW_JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-BILLBOARD-WITHDRAW-RISC0-STARK-V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqZkError {
    Prover,
    Verification,
    WrongReceiptKind,
    WrongPublicStatement,
}

#[must_use]
pub fn statement_for(secret: &[u8]) -> PublicStatement {
    PublicStatement(Sha3_256::digest(secret).into())
}

/// Proves knowledge of bytes opening `statement` without publishing the bytes.
pub fn prove(secret: &[u8], statement: PublicStatement) -> Result<PqZkProof, PqZkError> {
    if statement_for(secret) != statement {
        return Err(PqZkError::WrongPublicStatement);
    }
    let env = ExecutorEnv::builder()
        .write(&secret.to_vec())
        .map_err(|_| PqZkError::Prover)?
        .build()
        .map_err(|_| PqZkError::Prover)?;
    let receipt = default_prover()
        .prove_with_opts(env, GUEST_ELF, &ProverOpts::succinct())
        .map_err(|_| PqZkError::Prover)?
        .receipt;
    verify_receipt(&receipt, statement)?;
    Ok(PqZkProof { receipt })
}

/// Verifies the exact guest image, receipt kind, and public journal.
pub fn verify(proof: &PqZkProof, statement: PublicStatement) -> Result<(), PqZkError> {
    verify_receipt(&proof.receipt, statement)
}

fn verify_receipt(receipt: &Receipt, statement: PublicStatement) -> Result<(), PqZkError> {
    receipt.inner.succinct().map_err(|_| PqZkError::WrongReceiptKind)?;
    receipt.verify(GUEST_ID).map_err(|_| PqZkError::Verification)?;
    let mut expected = PROFILE_ID.as_bytes().to_vec();
    expected.extend_from_slice(&statement.0);
    if receipt.journal.bytes != expected {
        return Err(PqZkError::WrongPublicStatement);
    }
    Ok(())
}

fn relation_env<T: CanonicalType>(input: &T) -> Result<ExecutorEnv<'static>, PqZkError> {
    let encoded = encode_envelope(input).map_err(|_| PqZkError::Prover)?;
    ExecutorEnv::builder()
        .write(&encoded)
        .map_err(|_| PqZkError::Prover)?
        .build()
        .map_err(|_| PqZkError::Prover)
}

fn expected_relation_journal(domain: &[u8], public: Digest384, permit: Digest384) -> Vec<u8> {
    let mut expected = domain.to_vec();
    expected.extend_from_slice(public.as_bytes());
    expected.extend_from_slice(permit.as_bytes());
    expected
}

pub fn execute_post_relation(input: &PostRelationInput) -> Result<Vec<u8>, PqZkError> {
    default_executor()
        .execute(relation_env(input)?, BILLBOARD_POST_ELF)
        .map(|session| session.journal.bytes)
        .map_err(|_| PqZkError::Verification)
}

pub fn execute_withdrawal_relation(input: &WithdrawalRelationInput) -> Result<Vec<u8>, PqZkError> {
    default_executor()
        .execute(relation_env(input)?, BILLBOARD_WITHDRAW_ELF)
        .map(|session| session.journal.bytes)
        .map_err(|_| PqZkError::Verification)
}

pub fn prove_post_relation(input: &PostRelationInput) -> Result<BillboardPqZkProof, PqZkError> {
    let receipt = default_prover()
        .prove_with_opts(relation_env(input)?, BILLBOARD_POST_ELF, &ProverOpts::succinct())
        .map_err(|_| PqZkError::Prover)?
        .receipt;
    Ok(BillboardPqZkProof { receipt })
}

pub fn prove_withdrawal_relation(
    input: &WithdrawalRelationInput,
) -> Result<BillboardPqZkProof, PqZkError> {
    let receipt = default_prover()
        .prove_with_opts(relation_env(input)?, BILLBOARD_WITHDRAW_ELF, &ProverOpts::succinct())
        .map_err(|_| PqZkError::Prover)?
        .receipt;
    Ok(BillboardPqZkProof { receipt })
}

pub fn verify_post_relation(
    proof: &BillboardPqZkProof,
    public: Digest384,
    permit: Digest384,
) -> Result<(), PqZkError> {
    verify_billboard_receipt(proof, BILLBOARD_POST_ID, POST_JOURNAL_DOMAIN, public, permit)
}

pub fn verify_withdrawal_relation(
    proof: &BillboardPqZkProof,
    public: Digest384,
    permit: Digest384,
) -> Result<(), PqZkError> {
    verify_billboard_receipt(proof, BILLBOARD_WITHDRAW_ID, WITHDRAW_JOURNAL_DOMAIN, public, permit)
}

fn verify_billboard_receipt(
    proof: &BillboardPqZkProof,
    image_id: [u32; 8],
    domain: &[u8],
    public: Digest384,
    permit: Digest384,
) -> Result<(), PqZkError> {
    proof.receipt.inner.succinct().map_err(|_| PqZkError::WrongReceiptKind)?;
    proof.receipt.verify(image_id).map_err(|_| PqZkError::Verification)?;
    if proof.receipt.journal.bytes != expected_relation_journal(domain, public, permit) {
        return Err(PqZkError::WrongPublicStatement);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use activechain_canonical_codec::{decode_envelope, encode_envelope};
    use activechain_private_billboard::{
        BillboardConfig, BillboardPermit, BillboardVerifier, PostPublicInputs, PostRelationInput,
        PostWitness, WithdrawalPublicInputs, WithdrawalRelationInput, WithdrawalWitness,
        derive_post_successor,
    };
    use activechain_protocol_types::{AssetId, ChainId, Digest384, PrincipalId};

    use super::{PublicStatement, statement_for};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn billboard_relations() -> (PostRelationInput, WithdrawalRelationInput) {
        let config = BillboardConfig::new(
            ChainId::new(digest(1)),
            AssetId::new(digest(2)),
            100,
            10,
            3,
            20,
            5,
            2,
            7,
        )
        .unwrap();
        let prior = BillboardPermit::new(config, digest(3), 300, 0, digest(4)).unwrap();
        let successor =
            derive_post_successor(config, &prior, &[], digest(11), 10, digest(5), &[]).unwrap();
        let post = PostPublicInputs {
            chain_id: config.chain_id(),
            asset_id: config.asset_id(),
            anchor: digest(6),
            nullifier: prior.nullifier(digest(7)).unwrap(),
            successor_commitment: successor.commitment().unwrap(),
            post_id: digest(11),
            content: vec![],
            height: 10,
            fee: 2,
            dummy: true,
            policy_revision: 7,
        };
        let withdrawal = WithdrawalPublicInputs {
            chain_id: config.chain_id(),
            asset_id: config.asset_id(),
            anchor: digest(6),
            nullifier: successor.nullifier(digest(8)).unwrap(),
            recipient: PrincipalId::new(digest(9)),
            amount: successor.amount() - 1,
            fee: 1,
            height: 10,
            policy_revision: 7,
        };
        (
            PostRelationInput {
                config,
                public: post,
                witness: PostWitness {
                    prior,
                    successor: successor.clone(),
                    nullifier_key: digest(7),
                },
                decisions: vec![],
            },
            WithdrawalRelationInput {
                config,
                public: withdrawal,
                witness: WithdrawalWitness { permit: successor, nullifier_key: digest(8) },
                decisions: vec![],
            },
        )
    }

    #[test]
    fn statement_is_deterministic() {
        assert_eq!(
            statement_for(b"activechain-pq-zk-vector-1"),
            PublicStatement([
                0xcd, 0x7d, 0x2d, 0x92, 0xd6, 0x5e, 0x29, 0x91, 0xd4, 0x24, 0xd9, 0xf3, 0x6b, 0xfe,
                0xfc, 0xb8, 0xa9, 0x68, 0x02, 0x02, 0x24, 0xc7, 0x48, 0xeb, 0xd2, 0xc3, 0x20, 0xa3,
                0x66, 0xc8, 0x61, 0x63,
            ])
        );
        assert_ne!(statement_for(b"same"), statement_for(b"different"));
        assert_ne!(statement_for(b"same"), PublicStatement([0; 32]));
    }

    #[test]
    fn prover_rejects_a_false_opening_before_proving() {
        assert!(matches!(
            super::prove(b"secret", statement_for(b"other")),
            Err(super::PqZkError::WrongPublicStatement)
        ));
    }

    #[test]
    fn billboard_guests_differentially_match_reference_relations() {
        let (post, withdrawal) = billboard_relations();
        let post_reference = BillboardVerifier::verify_post(
            post.config,
            &post.public,
            &post.witness,
            &post.decisions,
        )
        .unwrap();
        let post_journal = super::execute_post_relation(&post).unwrap();
        assert_eq!(
            post_journal,
            super::expected_relation_journal(
                super::POST_JOURNAL_DOMAIN,
                post_reference.public_inputs_commitment(),
                post_reference.permit_commitment(),
            )
        );

        let withdrawal_reference = BillboardVerifier::verify_withdrawal(
            withdrawal.config,
            withdrawal.public,
            &withdrawal.witness,
            &withdrawal.decisions,
        )
        .unwrap();
        let withdrawal_journal = super::execute_withdrawal_relation(&withdrawal).unwrap();
        assert_eq!(
            withdrawal_journal,
            super::expected_relation_journal(
                super::WITHDRAW_JOURNAL_DOMAIN,
                withdrawal_reference.public_inputs_commitment(),
                withdrawal_reference.permit_commitment(),
            )
        );
    }

    #[test]
    fn billboard_guest_and_reference_both_reject_substituted_successor() {
        let (mut post, _) = billboard_relations();
        post.public.successor_commitment = digest(99);
        assert!(
            BillboardVerifier::verify_post(
                post.config,
                &post.public,
                &post.witness,
                &post.decisions,
            )
            .is_err()
        );
        assert!(super::execute_post_relation(&post).is_err());
    }

    #[test]
    fn billboard_image_ids_match_the_published_vector() {
        assert_eq!(
            activechain_pq_zk_methods::BILLBOARD_POST_ID,
            [
                2359650203, 825427449, 803873494, 7228888, 2393724673, 1052239005, 3492680221,
                851485700
            ]
        );
        assert_eq!(
            activechain_pq_zk_methods::BILLBOARD_WITHDRAW_ID,
            [
                792537467, 1516337779, 2206555091, 3776183473, 2265041217, 2279639786, 2725943854,
                2442665847
            ]
        );
        let vector = include_str!("../../../testing/vectors/pq-zk/billboard-relations-v1.txt");
        assert!(vector.contains("post_relation=private-billboard-post-v1"));
        assert!(vector.contains("withdrawal_relation=private-billboard-withdrawal-v1"));
    }

    #[test]
    fn billboard_relation_codec_rejects_truncation_and_trailing_bytes() {
        let (post, _) = billboard_relations();
        let encoded = encode_envelope(&post).unwrap();
        assert!(decode_envelope::<PostRelationInput>(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_envelope::<PostRelationInput>(&trailing).is_err());
    }

    #[test]
    fn billboard_guest_cycle_budget_is_reproducible() {
        let (post, withdrawal) = billboard_relations();
        let post_session = risc0_zkvm::default_executor()
            .execute(
                super::relation_env(&post).unwrap(),
                activechain_pq_zk_methods::BILLBOARD_POST_ELF,
            )
            .unwrap();
        let withdrawal_session = risc0_zkvm::default_executor()
            .execute(
                super::relation_env(&withdrawal).unwrap(),
                activechain_pq_zk_methods::BILLBOARD_WITHDRAW_ELF,
            )
            .unwrap();
        eprintln!("billboard-post-user-cycles={}", post_session.cycles());
        eprintln!("billboard-withdrawal-user-cycles={}", withdrawal_session.cycles());
        assert!(post_session.cycles() <= 1 << 22);
        assert!(withdrawal_session.cycles() <= 1 << 22);
    }

    #[test]
    #[ignore = "real succinct proving is an explicit release/security gate"]
    fn real_succinct_receipt_rejects_public_input_substitution() {
        let statement = statement_for(b"private witness");
        let proof = super::prove(b"private witness", statement).expect("prove");
        super::verify(&proof, statement).expect("verify");
        assert_eq!(
            super::verify(&proof, statement_for(b"different witness")),
            Err(super::PqZkError::WrongPublicStatement)
        );
        let mut malformed = super::PqZkProof { receipt: proof.receipt.clone() };
        malformed.receipt.journal.bytes[0] ^= 1;
        assert_eq!(super::verify(&malformed, statement), Err(super::PqZkError::Verification));
    }
}
