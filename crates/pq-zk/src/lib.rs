#![forbid(unsafe_code)]

//! ActiveChain PQ-ZK v1 transparent STARK profile.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_cash_air::{
    CashAggregationLeafInputV1, CashAggregationLevel, CashAggregationNodeV1,
    CashAggregationStatementV1, cash_aggregation_journal, recursive_cash_child_journals,
};
use activechain_pq_zk_methods::{
    ACTIVECHAIN_PQ_ZK_GUEST_ELF as GUEST_ELF, ACTIVECHAIN_PQ_ZK_GUEST_ID as GUEST_ID,
    BILLBOARD_POST_ELF, BILLBOARD_POST_ID, BILLBOARD_WITHDRAW_ELF, BILLBOARD_WITHDRAW_ID,
    CASH_RECURSIVE_GLOBAL_ELF, CASH_RECURSIVE_GLOBAL_ID, CASH_RECURSIVE_LEAF_ELF,
    CASH_RECURSIVE_LEAF_ID, CASH_RECURSIVE_MICROBATCH_ELF, CASH_RECURSIVE_MICROBATCH_ID,
    CASH_RECURSIVE_PARTITION_ELF, CASH_RECURSIVE_PARTITION_ID, CASH_RECURSIVE_SLOT_ELF,
    CASH_RECURSIVE_SLOT_ID, PRIVATE_IDENTITY_ELF, PRIVATE_IDENTITY_ID, PROOF_OF_FUNDS_ELF,
    PROOF_OF_FUNDS_ID, WORK_NON_OVERLAP_ELF, WORK_NON_OVERLAP_ID,
};
use activechain_privacy_kernel::{PrivateIdentityRelationInputV1, ProofOfFundsRelationInputV1};
use activechain_private_billboard::{PostRelationInput, WithdrawalRelationInput};
use activechain_protocol_types::Digest384;
use activechain_work_proof::{WorkClaimPublicV1, WorkClaimRelationInputV1, public_journal};
use risc0_zkvm::{ExecutorEnv, ProverOpts, Receipt, default_executor, default_prover};
use sha3::{Digest, Sha3_256, Sha3_384};

/// Consensus-visible identifier for this exact proof profile.
pub const PROFILE_ID: &str = "ACTIVECHAIN-PQ-ZK-RISC0-STARK-V1";
pub const MAX_WORK_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_WORK_JOURNAL_BYTES: usize = 64 * 1024;
pub const WORK_PROOF_SYSTEM_REVISION: u32 = 3_000_005;

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
pub struct ProofOfFundsPqZkProof {
    receipt: Receipt,
}
pub struct PrivateIdentityPqZkProof {
    receipt: Receipt,
}
pub struct WorkNonOverlapProof {
    receipt: Receipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkProofReceiptEnvelopeV1 {
    profile_revision: u16,
    proof_system_revision: u32,
    image_id: [u8; 32],
    journal_revision: u16,
    journal: Vec<u8>,
    journal_commitment: Digest384,
    receipt_encoding: u8,
    receipt_bytes: Vec<u8>,
    receipt_commitment: Digest384,
}

pub fn work_image_id() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (output, word) in bytes.chunks_exact_mut(4).zip(WORK_NON_OVERLAP_ID) {
        output.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn transport_commitment(domain: &[u8], bytes: &[u8]) -> Digest384 {
    let mut hash = Sha3_384::new();
    hash.update(domain);
    hash.update(bytes);
    Digest384::new(hash.finalize().into())
}
impl CanonicalEncode for WorkProofReceiptEnvelopeV1 {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.profile_revision.encode(e)?;
        self.proof_system_revision.encode(e)?;
        self.image_id.encode(e)?;
        self.journal_revision.encode(e)?;
        e.write_bytes(&self.journal, MAX_WORK_JOURNAL_BYTES)?;
        self.journal_commitment.encode(e)?;
        self.receipt_encoding.encode(e)?;
        e.write_bytes(&self.receipt_bytes, MAX_WORK_PROOF_BYTES)?;
        self.receipt_commitment.encode(e)
    }
}
impl CanonicalDecode for WorkProofReceiptEnvelopeV1 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            profile_revision: u16::decode(d)?,
            proof_system_revision: u32::decode(d)?,
            image_id: <[u8; 32]>::decode(d)?,
            journal_revision: u16::decode(d)?,
            journal: d.read_bytes(MAX_WORK_JOURNAL_BYTES)?.to_vec(),
            journal_commitment: Digest384::decode(d)?,
            receipt_encoding: u8::decode(d)?,
            receipt_bytes: d.read_bytes(MAX_WORK_PROOF_BYTES)?.to_vec(),
            receipt_commitment: Digest384::decode(d)?,
        })
    }
}
impl CanonicalType for WorkProofReceiptEnvelopeV1 {
    const TYPE_TAG: u16 = 0x01BD;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize =
        2 + 4 + 32 + 2 + 4 + MAX_WORK_JOURNAL_BYTES + 48 + 1 + 4 + MAX_WORK_PROOF_BYTES + 48;
}

/// An unconditional RISC Zero receipt for one level of the recursive cash tree.
pub struct RecursiveCashProof {
    receipt: Receipt,
    node: CashAggregationNodeV1,
    image_id: [u32; 8],
}

const POST_JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-BILLBOARD-POST-RISC0-STARK-V1";
const WITHDRAW_JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-BILLBOARD-WITHDRAW-RISC0-STARK-V1";
const PROOF_OF_FUNDS_JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-PROOF-OF-FUNDS-RISC0-STARK-V1";
const PRIVATE_IDENTITY_JOURNAL_DOMAIN: &[u8] = b"ACTIVECHAIN-PRIVATE-IDENTITY-RISC0-STARK-V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqZkError {
    Prover,
    Verification,
    MalformedProof,
    ProofTooLarge,
    WrongReceiptKind,
    WrongPublicStatement,
}

struct RecursiveCashMethod {
    elf: &'static [u8],
    image_id: [u32; 8],
    child_image_id: [u32; 8],
}

fn recursive_cash_method(level: CashAggregationLevel) -> Result<RecursiveCashMethod, PqZkError> {
    match level {
        CashAggregationLevel::Microbatch => Ok(RecursiveCashMethod {
            elf: CASH_RECURSIVE_MICROBATCH_ELF,
            image_id: CASH_RECURSIVE_MICROBATCH_ID,
            child_image_id: CASH_RECURSIVE_LEAF_ID,
        }),
        CashAggregationLevel::Partition => Ok(RecursiveCashMethod {
            elf: CASH_RECURSIVE_PARTITION_ELF,
            image_id: CASH_RECURSIVE_PARTITION_ID,
            child_image_id: CASH_RECURSIVE_MICROBATCH_ID,
        }),
        CashAggregationLevel::CashSlot => Ok(RecursiveCashMethod {
            elf: CASH_RECURSIVE_SLOT_ELF,
            image_id: CASH_RECURSIVE_SLOT_ID,
            child_image_id: CASH_RECURSIVE_PARTITION_ID,
        }),
        CashAggregationLevel::GlobalTransition => Ok(RecursiveCashMethod {
            elf: CASH_RECURSIVE_GLOBAL_ELF,
            image_id: CASH_RECURSIVE_GLOBAL_ID,
            child_image_id: CASH_RECURSIVE_SLOT_ID,
        }),
        CashAggregationLevel::Proof => Err(PqZkError::WrongPublicStatement),
    }
}

fn verify_recursive_cash_receipt(
    receipt: &Receipt,
    image_id: [u32; 8],
    node: &CashAggregationNodeV1,
) -> Result<(), PqZkError> {
    receipt.inner.succinct().map_err(|_| PqZkError::WrongReceiptKind)?;
    receipt.verify(image_id).map_err(|_| PqZkError::Verification)?;
    let expected = cash_aggregation_journal(node).map_err(|_| PqZkError::WrongPublicStatement)?;
    if receipt.journal.bytes != expected {
        return Err(PqZkError::WrongPublicStatement);
    }
    Ok(())
}

/// Proves one fully authenticated CashAIR payment leaf inside the pinned RISC Zero guest.
pub fn prove_recursive_cash_leaf(
    input: &CashAggregationLeafInputV1,
) -> Result<RecursiveCashProof, PqZkError> {
    let node = input.verify().map_err(|_| PqZkError::WrongPublicStatement)?;
    let encoded = encode_envelope(input).map_err(|_| PqZkError::Prover)?;
    let env = ExecutorEnv::builder()
        .write(&encoded)
        .map_err(|_| PqZkError::Prover)?
        .build()
        .map_err(|_| PqZkError::Prover)?;
    let receipt = default_prover()
        .prove_with_opts(env, CASH_RECURSIVE_LEAF_ELF, &ProverOpts::succinct())
        .map_err(|_| PqZkError::Prover)?
        .receipt;
    verify_recursive_cash_receipt(&receipt, CASH_RECURSIVE_LEAF_ID, &node)?;
    Ok(RecursiveCashProof { receipt, node, image_id: CASH_RECURSIVE_LEAF_ID })
}

/// Recursively proves one canonical microbatch, partition, slot, or global transition.
/// Every child receipt is attached as a proven assumption and the resulting receipt is required
/// to be unconditional before it is returned.
pub fn prove_recursive_cash_aggregation(
    statement: &CashAggregationStatementV1,
    children: &[RecursiveCashProof],
) -> Result<RecursiveCashProof, PqZkError> {
    let method = recursive_cash_method(statement.level())?;
    let journals =
        recursive_cash_child_journals(statement, statement.level(), &method.child_image_id)
            .map_err(|_| PqZkError::WrongPublicStatement)?;
    if children.len() != journals.len() {
        return Err(PqZkError::WrongPublicStatement);
    }
    let encoded = encode_envelope(statement).map_err(|_| PqZkError::Prover)?;
    let mut builder = ExecutorEnv::builder();
    builder.write(&encoded).map_err(|_| PqZkError::Prover)?;
    for (child, journal) in children.iter().zip(&journals) {
        if child.image_id != method.child_image_id || child.receipt.journal.bytes != *journal {
            return Err(PqZkError::WrongPublicStatement);
        }
        verify_recursive_cash_receipt(&child.receipt, method.child_image_id, &child.node)?;
        builder.add_assumption(child.receipt.clone());
    }
    let env = builder.build().map_err(|_| PqZkError::Prover)?;
    let receipt = default_prover()
        .prove_with_opts(env, method.elf, &ProverOpts::succinct())
        .map_err(|_| PqZkError::Prover)?
        .receipt;
    let node = CashAggregationNodeV1::from_statement(statement);
    verify_recursive_cash_receipt(&receipt, method.image_id, &node)?;
    Ok(RecursiveCashProof { receipt, node, image_id: method.image_id })
}

pub fn verify_recursive_cash_proof(
    proof: &RecursiveCashProof,
    expected: &CashAggregationNodeV1,
) -> Result<(), PqZkError> {
    if &proof.node != expected {
        return Err(PqZkError::WrongPublicStatement);
    }
    verify_recursive_cash_receipt(&proof.receipt, proof.image_id, expected)
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

pub fn execute_proof_of_funds_relation(
    input: &ProofOfFundsRelationInputV1,
) -> Result<Vec<u8>, PqZkError> {
    default_executor()
        .execute(relation_env(input)?, PROOF_OF_FUNDS_ELF)
        .map(|session| session.journal.bytes)
        .map_err(|_| PqZkError::Verification)
}

pub fn prove_proof_of_funds(
    input: &ProofOfFundsRelationInputV1,
) -> Result<ProofOfFundsPqZkProof, PqZkError> {
    let receipt = default_prover()
        .prove_with_opts(relation_env(input)?, PROOF_OF_FUNDS_ELF, &ProverOpts::succinct())
        .map_err(|_| PqZkError::Prover)?
        .receipt;
    let proof = ProofOfFundsPqZkProof { receipt };
    verify_proof_of_funds(
        &proof,
        input.public.commitment().map_err(|_| PqZkError::WrongPublicStatement)?,
        input.public.predicate.nonce(),
    )?;
    Ok(proof)
}

pub fn verify_proof_of_funds(
    proof: &ProofOfFundsPqZkProof,
    predicate: Digest384,
    nullifier: Digest384,
) -> Result<(), PqZkError> {
    proof.receipt.inner.succinct().map_err(|_| PqZkError::WrongReceiptKind)?;
    proof.receipt.verify(PROOF_OF_FUNDS_ID).map_err(|_| PqZkError::Verification)?;
    let mut expected = PROOF_OF_FUNDS_JOURNAL_DOMAIN.to_vec();
    expected.extend_from_slice(predicate.as_bytes());
    expected.extend_from_slice(nullifier.as_bytes());
    if proof.receipt.journal.bytes != expected {
        return Err(PqZkError::WrongPublicStatement);
    }
    Ok(())
}

pub fn execute_private_identity_relation(
    input: &PrivateIdentityRelationInputV1,
) -> Result<Vec<u8>, PqZkError> {
    default_executor()
        .execute(relation_env(input)?, PRIVATE_IDENTITY_ELF)
        .map(|session| session.journal.bytes)
        .map_err(|_| PqZkError::Verification)
}

pub fn execute_work_non_overlap_relation(
    input: &WorkClaimRelationInputV1,
) -> Result<Vec<u8>, PqZkError> {
    default_executor()
        .execute(relation_env(input)?, WORK_NON_OVERLAP_ELF)
        .map(|session| session.journal.bytes)
        .map_err(|_| PqZkError::Verification)
}

pub fn prove_work_non_overlap(
    input: &WorkClaimRelationInputV1,
) -> Result<WorkNonOverlapProof, PqZkError> {
    let receipt = default_prover()
        .prove_with_opts(relation_env(input)?, WORK_NON_OVERLAP_ELF, &ProverOpts::succinct())
        .map_err(|_| PqZkError::Prover)?
        .receipt;
    let proof = WorkNonOverlapProof { receipt };
    verify_work_non_overlap(&proof, &input.public)?;
    Ok(proof)
}

pub fn verify_work_non_overlap(
    proof: &WorkNonOverlapProof,
    public: &WorkClaimPublicV1,
) -> Result<(), PqZkError> {
    proof.receipt.inner.succinct().map_err(|_| PqZkError::WrongReceiptKind)?;
    proof.receipt.verify(WORK_NON_OVERLAP_ID).map_err(|_| PqZkError::Verification)?;
    let expected = public_journal(public).map_err(|_| PqZkError::WrongPublicStatement)?;
    if proof.receipt.journal.bytes != expected {
        return Err(PqZkError::WrongPublicStatement);
    }
    Ok(())
}

impl WorkNonOverlapProof {
    pub fn to_envelope_bytes(&self) -> Result<Vec<u8>, PqZkError> {
        let receipt_bytes =
            rmp_serde::to_vec(&self.receipt).map_err(|_| PqZkError::MalformedProof)?;
        if receipt_bytes.is_empty()
            || receipt_bytes.len() > MAX_WORK_PROOF_BYTES
            || self.receipt.journal.bytes.len() > MAX_WORK_JOURNAL_BYTES
        {
            return Err(PqZkError::ProofTooLarge);
        }
        let envelope = WorkProofReceiptEnvelopeV1 {
            profile_revision: 1,
            proof_system_revision: WORK_PROOF_SYSTEM_REVISION,
            image_id: work_image_id(),
            journal_revision: 1,
            journal: self.receipt.journal.bytes.clone(),
            journal_commitment: transport_commitment(
                b"ACTUM-WORK-JOURNAL-V1",
                &self.receipt.journal.bytes,
            ),
            receipt_commitment: transport_commitment(b"ACTUM-WORK-RECEIPT-V1", &receipt_bytes),
            receipt_encoding: 1,
            receipt_bytes,
        };
        encode_envelope(&envelope).map_err(|_| PqZkError::MalformedProof)
    }

    pub fn from_envelope_bytes(
        bytes: &[u8],
        public: &WorkClaimPublicV1,
    ) -> Result<Self, PqZkError> {
        if bytes.is_empty() || bytes.len() > WorkProofReceiptEnvelopeV1::MAX_ENCODED_LEN + 9 {
            return Err(PqZkError::ProofTooLarge);
        }
        let envelope = decode_envelope::<WorkProofReceiptEnvelopeV1>(bytes)
            .map_err(|_| PqZkError::MalformedProof)?;
        let expected_journal =
            public_journal(public).map_err(|_| PqZkError::WrongPublicStatement)?;
        if envelope.profile_revision != 1
            || envelope.proof_system_revision != WORK_PROOF_SYSTEM_REVISION
            || envelope.image_id != work_image_id()
            || envelope.journal_revision != 1
            || envelope.receipt_encoding != 1
            || envelope.journal != expected_journal
            || envelope.journal_commitment
                != transport_commitment(b"ACTUM-WORK-JOURNAL-V1", &envelope.journal)
            || envelope.receipt_commitment
                != transport_commitment(b"ACTUM-WORK-RECEIPT-V1", &envelope.receipt_bytes)
        {
            return Err(PqZkError::WrongPublicStatement);
        }
        let receipt = rmp_serde::from_slice(&envelope.receipt_bytes)
            .map_err(|_| PqZkError::MalformedProof)?;
        let proof = Self { receipt };
        verify_work_non_overlap(&proof, public)?;
        Ok(proof)
    }
}
pub fn prove_private_identity(
    input: &PrivateIdentityRelationInputV1,
) -> Result<PrivateIdentityPqZkProof, PqZkError> {
    let receipt = default_prover()
        .prove_with_opts(relation_env(input)?, PRIVATE_IDENTITY_ELF, &ProverOpts::succinct())
        .map_err(|_| PqZkError::Prover)?
        .receipt;
    let proof = PrivateIdentityPqZkProof { receipt };
    verify_private_identity(
        &proof,
        input.public.commitment().map_err(|_| PqZkError::WrongPublicStatement)?,
        input.public.nonce,
    )?;
    Ok(proof)
}
pub fn verify_private_identity(
    proof: &PrivateIdentityPqZkProof,
    public: Digest384,
    nullifier: Digest384,
) -> Result<(), PqZkError> {
    proof.receipt.inner.succinct().map_err(|_| PqZkError::WrongReceiptKind)?;
    proof.receipt.verify(PRIVATE_IDENTITY_ID).map_err(|_| PqZkError::Verification)?;
    let mut expected = PRIVATE_IDENTITY_JOURNAL_DOMAIN.to_vec();
    expected.extend_from_slice(public.as_bytes());
    expected.extend_from_slice(nullifier.as_bytes());
    if proof.receipt.journal.bytes != expected {
        return Err(PqZkError::WrongPublicStatement);
    }
    Ok(())
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

    fn work_input() -> activechain_work_proof::WorkClaimRelationInputV1 {
        let vector = include_str!("../../../testing/vectors/application/work-claim-v1.txt");
        let envelope =
            vector.lines().find_map(|line| line.strip_prefix("relation_envelope=")).unwrap();
        decode_envelope(&decode_hex(envelope)).unwrap()
    }

    #[test]
    fn work_guest_image_and_journal_match_published_vector() {
        let vector = include_str!("../../../testing/vectors/pq-zk/work-non-overlap-v1.txt");
        let image: [u32; 8] = vector
            .lines()
            .find_map(|line| line.strip_prefix("image_id_u32_le="))
            .unwrap()
            .split(',')
            .map(|word| word.parse().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(activechain_pq_zk_methods::WORK_NON_OVERLAP_ID, image);
        let expected_journal =
            vector.lines().find_map(|line| line.strip_prefix("journal=")).map(decode_hex).unwrap();
        assert_eq!(super::execute_work_non_overlap_relation(&work_input()), Ok(expected_journal));
    }

    #[test]
    fn work_receipt_envelope_metadata_substitution_fails_before_deserialization() {
        let input = work_input();
        let journal = activechain_work_proof::public_journal(&input.public).unwrap();
        let receipt = vec![1_u8];
        let mut envelope = super::WorkProofReceiptEnvelopeV1 {
            profile_revision: 1,
            proof_system_revision: super::WORK_PROOF_SYSTEM_REVISION,
            image_id: super::work_image_id(),
            journal_revision: 1,
            journal: journal.clone(),
            journal_commitment: super::transport_commitment(b"ACTUM-WORK-JOURNAL-V1", &journal),
            receipt_encoding: 1,
            receipt_commitment: super::transport_commitment(b"ACTUM-WORK-RECEIPT-V1", &receipt),
            receipt_bytes: receipt,
        };
        let mut encoded = encode_envelope(&envelope).unwrap();
        assert!(matches!(
            super::WorkNonOverlapProof::from_envelope_bytes(&encoded, &input.public),
            Err(super::PqZkError::MalformedProof)
        ));
        envelope.image_id[0] ^= 1;
        encoded = encode_envelope(&envelope).unwrap();
        assert!(matches!(
            super::WorkNonOverlapProof::from_envelope_bytes(&encoded, &input.public),
            Err(super::PqZkError::WrongPublicStatement)
        ));
        envelope.image_id = super::work_image_id();
        envelope.journal[0] ^= 1;
        envelope.journal_commitment =
            super::transport_commitment(b"ACTUM-WORK-JOURNAL-V1", &envelope.journal);
        encoded = encode_envelope(&envelope).unwrap();
        assert!(matches!(
            super::WorkNonOverlapProof::from_envelope_bytes(&encoded, &input.public),
            Err(super::PqZkError::WrongPublicStatement)
        ));
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
    fn all_recursive_cash_guests_require_the_pinned_child_claim() {
        use activechain_cash_air::{
            CashAggregationChildV1, CashAggregationLevel, CashAggregationNodeV1,
            CashAggregationStatementV1, cash_aggregation_journal, recursive_cash_child_journals,
        };
        use risc0_zkvm::ReceiptClaim;

        let cases = [
            (
                CashAggregationLevel::Microbatch,
                3,
                CashAggregationLevel::Proof,
                3,
                activechain_pq_zk_methods::CASH_RECURSIVE_LEAF_ID,
                activechain_pq_zk_methods::CASH_RECURSIVE_MICROBATCH_ELF,
            ),
            (
                CashAggregationLevel::Partition,
                3,
                CashAggregationLevel::Microbatch,
                3,
                activechain_pq_zk_methods::CASH_RECURSIVE_MICROBATCH_ID,
                activechain_pq_zk_methods::CASH_RECURSIVE_PARTITION_ELF,
            ),
            (
                CashAggregationLevel::CashSlot,
                activechain_cash_air::GLOBAL_CASH_PARTITION,
                CashAggregationLevel::Partition,
                3,
                activechain_pq_zk_methods::CASH_RECURSIVE_PARTITION_ID,
                activechain_pq_zk_methods::CASH_RECURSIVE_SLOT_ELF,
            ),
            (
                CashAggregationLevel::GlobalTransition,
                activechain_cash_air::GLOBAL_CASH_PARTITION,
                CashAggregationLevel::CashSlot,
                activechain_cash_air::GLOBAL_CASH_PARTITION,
                activechain_pq_zk_methods::CASH_RECURSIVE_SLOT_ID,
                activechain_pq_zk_methods::CASH_RECURSIVE_GLOBAL_ELF,
            ),
        ];
        for (level, partition, child_level, child_partition, child_image_id, elf) in cases {
            let chain_id = ChainId::new(digest(1));
            let child = CashAggregationChildV1::new_recursive(
                chain_id,
                9,
                child_level,
                child_partition,
                digest(10),
                digest(11),
                1,
                0,
                7,
                &child_image_id,
            )
            .unwrap();
            let statement = CashAggregationStatementV1::new(
                chain_id,
                9,
                level,
                partition,
                digest(10),
                digest(11),
                1,
                0,
                7,
                vec![child],
            )
            .unwrap();
            let child_journal = recursive_cash_child_journals(&statement, level, &child_image_id)
                .unwrap()
                .remove(0);
            let claim = ReceiptClaim::ok(child_image_id, child_journal);
            let encoded = encode_envelope(&statement).unwrap();
            let mut builder = risc0_zkvm::ExecutorEnv::builder();
            builder.write(&encoded).unwrap().add_assumption(claim);
            let session =
                risc0_zkvm::default_executor().execute(builder.build().unwrap(), elf).unwrap();
            assert_eq!(
                session.journal.bytes,
                cash_aggregation_journal(&CashAggregationNodeV1::from_statement(&statement))
                    .unwrap()
            );
        }
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

    #[cfg(feature = "reproducible-build")]
    #[test]
    fn billboard_image_ids_match_the_published_vector() {
        fn published_id(vector: &str, key: &str) -> [u32; 8] {
            let value = vector
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .expect("published image ID entry");
            let words: Vec<u32> =
                value.split(',').map(|word| word.parse().expect("decimal image ID word")).collect();
            words.try_into().expect("exact eight-word image ID")
        }

        let vector = include_str!("../../../testing/vectors/pq-zk/billboard-relations-v1.txt");
        assert_eq!(
            activechain_pq_zk_methods::BILLBOARD_POST_ID,
            published_id(vector, "post_image_id_u32_le=")
        );
        assert_eq!(
            activechain_pq_zk_methods::BILLBOARD_WITHDRAW_ID,
            published_id(vector, "withdrawal_image_id_u32_le=")
        );
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
    fn proof_of_funds_guest_enforces_private_range_and_exact_public_journal() {
        use activechain_privacy_kernel::{
            ProofOfFundsPublicInputsV1, ProofOfFundsRelationInputV1, ProofOfFundsWitnessV1,
        };
        use activechain_protocol_types::{
            AssetId, ChainId, CredentialAssuranceClassV1, PrincipalId, ProofOfFundsPredicateV1,
            TransactionId,
        };
        let d = |n| Digest384::new([n; 48]);
        let predicate = ProofOfFundsPredicateV1::new(
            d(1),
            d(2),
            d(3),
            ChainId::new(d(4)),
            PrincipalId::new(d(5)),
            TransactionId::new(d(6)),
            d(7),
            d(8),
            Some(AssetId::new(d(9))),
            2,
            10_000,
            Some(20_000),
            d(10),
            d(11),
            1,
            80,
            90,
            110,
        )
        .unwrap();
        let input = ProofOfFundsRelationInputV1 {
            public: ProofOfFundsPublicInputsV1::new(
                predicate,
                d(12),
                PrincipalId::new(d(13)),
                d(14),
                d(15),
                CredentialAssuranceClassV1::HolderSelfIssued,
                None,
                100,
            )
            .unwrap(),
            witness: ProofOfFundsWitnessV1 {
                amount_units: 15_000,
                decimals: 2,
                currency_commitment: d(8),
                institution_set_commitment: d(10),
                holder_binding: d(3),
                evidence_commitment: d(1),
                aggregation_rule_commitment: d(11),
                observation_count: 1,
            },
        };
        let journal = super::execute_proof_of_funds_relation(&input).unwrap();
        assert_eq!(
            journal,
            super::expected_relation_journal(
                super::PROOF_OF_FUNDS_JOURNAL_DOMAIN,
                input.public.commitment().unwrap(),
                predicate.nonce()
            )
        );
        let mut below = input;
        below.witness.amount_units = 9_999;
        assert!(super::execute_proof_of_funds_relation(&below).is_err());
    }

    #[test]
    fn proof_of_funds_image_id_matches_published_vector() {
        let vector = include_str!("../../../testing/vectors/pq-zk/proof-of-funds-v1.txt");
        let words: Vec<u32> = vector
            .lines()
            .find_map(|line| line.strip_prefix("image_id_u32_le="))
            .unwrap()
            .split(',')
            .map(|word| word.parse().unwrap())
            .collect();
        let published: [u32; 8] = words.try_into().unwrap();
        assert_eq!(activechain_pq_zk_methods::PROOF_OF_FUNDS_ID, published);
        assert!(vector.contains("journal=domain||public_inputs_commitment_48||nullifier_48"));
    }

    #[test]
    fn private_identity_guest_enforces_age_without_journaling_birth_date() {
        use activechain_privacy_kernel::{
            CanonicalDateV1, PrivateIdentityPredicateKindV1, PrivateIdentityPublicInputsV1,
            PrivateIdentityRelationInputV1, PrivateIdentityWitnessV1,
        };
        use activechain_protocol_types::{AssetId, ChainId, PrincipalId, TransactionId};
        let d = |n| Digest384::new([n; 48]);
        let public = PrivateIdentityPublicInputsV1::new(
            PrivateIdentityPredicateKindV1::AgeAtLeast,
            Some(18),
            None,
            Some(CanonicalDateV1::new(2026, 8, 2).unwrap()),
            None,
            None,
            ChainId::new(d(1)),
            d(2),
            Some(AssetId::new(d(3))),
            TransactionId::new(d(4)),
            PrincipalId::new(d(5)),
            PrincipalId::new(d(6)),
            d(7),
            1,
            d(8),
            20,
            10,
            d(9),
            PrincipalId::new(d(10)),
            d(11),
            d(12),
            d(13),
            1,
        )
        .unwrap();
        let input = PrivateIdentityRelationInputV1 {
            public,
            witness: PrivateIdentityWitnessV1 {
                date_of_birth: Some(CanonicalDateV1::new(2008, 8, 2).unwrap()),
                jurisdiction: None,
                registry_entries: vec![],
            },
        };
        let journal = super::execute_private_identity_relation(&input).unwrap();
        assert_eq!(
            journal,
            super::expected_relation_journal(
                super::PRIVATE_IDENTITY_JOURNAL_DOMAIN,
                public.commitment().unwrap(),
                public.nonce
            )
        );
        assert!(!journal.windows(4).any(|w| w == [0x07, 0xd8, 8, 2]));
        let mut underage = input.clone();
        underage.witness.date_of_birth = Some(CanonicalDateV1::new(2008, 8, 3).unwrap());
        assert!(super::execute_private_identity_relation(&underage).is_err());
    }
    #[test]
    fn private_identity_image_id_matches_published_vector() {
        let vector = include_str!("../../../testing/vectors/pq-zk/private-identity-v1.txt");
        let words: Vec<u32> = vector
            .lines()
            .find_map(|line| line.strip_prefix("image_id_u32_le="))
            .unwrap()
            .split(',')
            .map(|word| word.parse().unwrap())
            .collect();
        let published: [u32; 8] = words.try_into().unwrap();
        assert_eq!(activechain_pq_zk_methods::PRIVATE_IDENTITY_ID, published);
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
