#![forbid(unsafe_code)]

//! ActiveChain PQ-ZK v1 transparent STARK profile.

use activechain_pq_zk_methods::{
    ACTIVECHAIN_PQ_ZK_GUEST_ELF as GUEST_ELF, ACTIVECHAIN_PQ_ZK_GUEST_ID as GUEST_ID,
};
use risc0_zkvm::{ExecutorEnv, ProverOpts, Receipt, default_prover};
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

#[cfg(test)]
mod tests {
    use super::{PublicStatement, statement_for};

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
