use std::panic::{AssertUnwindSafe, catch_unwind};

use thiserror::Error;
use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
use winterfell::math::fields::f64::BaseElement;
use winterfell::{AcceptableOptions, Proof};

use crate::air::{AccumulatorAir, AccumulatorInputs};
use crate::codec::{CodecError, Receipt};
use crate::hash::Shake256_384;
use crate::model::{Block, ModelError, state_root};
use crate::suite::{
    MAX_TRACE_LENGTH, MIN_CONJECTURED_SOUNDNESS_BITS, PROTOCOL_VERSION, RECEIPT_CODEC_VERSION,
    RECEIPT_KIND_EXECUTION, SUITE_ID, TRACE_WIDTH, VERIFIER_VERSION, program_id, proof_options,
    trace_length,
};

type SuiteHasher = Shake256_384<BaseElement>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExpectedContext {
    pub protocol_version: u32,
    pub verifier_version: u32,
    pub program_id: [u8; 48],
    pub pre_state_root: [u8; 48],
    pub block_id: [u8; 48],
    pub post_state_root: [u8; 48],
}

impl ExpectedContext {
    pub fn active(pre_state: u64, block: &Block, post_state: u64) -> Result<Self, ModelError> {
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            verifier_version: VERIFIER_VERSION,
            program_id: program_id(),
            pre_state_root: state_root(pre_state)?,
            block_id: block.id()?,
            post_state_root: state_root(post_state)?,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerificationReport {
    pub receipt_bytes: usize,
    pub proof_bytes: usize,
    pub trace_length: usize,
    pub action_count: usize,
    pub conjectured_soundness_bits: u32,
    pub proven_ldr_bits: u32,
    pub proven_udr_bits: u32,
    pub post_state: u64,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("unregistered receipt kind {0}")]
    ReceiptKind(u16),
    #[error("unregistered protocol version {0}")]
    ProtocolVersion(u32),
    #[error("unregistered verifier version {0}")]
    VerifierVersion(u32),
    #[error("unregistered proof suite {0:#010x}")]
    Suite(u32),
    #[error("unregistered program identity")]
    ProgramIdentity,
    #[error("receipt does not match expected {0}")]
    ContextMismatch(&'static str),
    #[error("malformed STARK proof: {0}")]
    ProofDecode(String),
    #[error("proof uses an unregistered parameter set")]
    ProofParameters,
    #[error("proof trace shape is not registered")]
    TraceShape,
    #[error("proof's claimed conjectured soundness is below {minimum} bits: {actual} bits")]
    Soundness { minimum: u32, actual: u32 },
    #[error("STARK verification failed: {0}")]
    Stark(String),
    #[error("the underlying verifier panicked; receipt rejected")]
    VerifierPanic,
    #[error(transparent)]
    Model(#[from] ModelError),
}

pub fn verify_receipt(
    receipt_bytes: &[u8],
    expected: Option<&ExpectedContext>,
) -> Result<VerificationReport, VerifyError> {
    let receipt = Receipt::decode(receipt_bytes)?;
    verify_registered_header(&receipt)?;
    receipt
        .header
        .validate_bindings(receipt.pre_state, receipt.post_state, &receipt.block)?;
    if let Some(expected) = expected {
        verify_expected(&receipt, expected)?;
    }

    let proof = catch_unwind(AssertUnwindSafe(|| Proof::from_bytes(&receipt.proof)))
        .map_err(|_| VerifyError::VerifierPanic)?
        .map_err(|e| VerifyError::ProofDecode(e.to_string()))?;

    if proof.options() != &proof_options() {
        return Err(VerifyError::ProofParameters);
    }
    let expected_trace = trace_length(receipt.block.actions.len());
    if proof.trace_info().width() != TRACE_WIDTH
        || proof.trace_info().length() != expected_trace
        || expected_trace > MAX_TRACE_LENGTH
    {
        return Err(VerifyError::TraceShape);
    }

    let conjectured = proof.conjectured_security::<SuiteHasher>().bits();
    let proven = proof.proven_security::<SuiteHasher>();
    let proven_ldr = proven.ldr_bits();
    let proven_udr = proven.udr_bits();
    if conjectured < MIN_CONJECTURED_SOUNDNESS_BITS {
        return Err(VerifyError::Soundness {
            minimum: MIN_CONJECTURED_SOUNDNESS_BITS,
            actual: conjectured,
        });
    }

    let public_inputs = AccumulatorInputs::new(
        receipt.header.clone(),
        receipt.pre_state,
        receipt.post_state,
        &receipt.block,
    )?;
    let acceptable = AcceptableOptions::OptionSet(vec![proof_options()]);
    catch_unwind(AssertUnwindSafe(|| {
        winterfell::verify::<
            AccumulatorAir,
            SuiteHasher,
            DefaultRandomCoin<SuiteHasher>,
            MerkleTree<SuiteHasher>,
        >(proof, public_inputs, &acceptable)
    }))
    .map_err(|_| VerifyError::VerifierPanic)?
    .map_err(|e| VerifyError::Stark(e.to_string()))?;

    Ok(VerificationReport {
        receipt_bytes: receipt_bytes.len(),
        proof_bytes: receipt.proof.len(),
        trace_length: expected_trace,
        action_count: receipt.block.actions.len(),
        conjectured_soundness_bits: conjectured,
        proven_ldr_bits: proven_ldr,
        proven_udr_bits: proven_udr,
        post_state: receipt.post_state,
    })
}

/// Independent semantic cross-check for clients that do not embed Winterfell.
/// This verifies canonical decoding, all protocol bindings, and re-executes the
/// transition; it deliberately does not treat model execution as a substitute
/// for cryptographic proof verification.
pub fn verify_model_receipt(receipt_bytes: &[u8]) -> Result<u64, VerifyError> {
    let receipt = Receipt::decode(receipt_bytes)?;
    receipt
        .header
        .validate_bindings(receipt.pre_state, receipt.post_state, &receipt.block)?;
    let recomputed = receipt.block.execute(receipt.pre_state)?;
    if recomputed != receipt.post_state {
        return Err(VerifyError::ContextMismatch("model post-state"));
    }
    Ok(recomputed)
}

fn verify_registered_header(receipt: &Receipt) -> Result<(), VerifyError> {
    let h = &receipt.header;
    if h.codec_version != RECEIPT_CODEC_VERSION {
        return Err(CodecError::Malformed("unknown receipt codec version").into());
    }
    if h.receipt_kind != RECEIPT_KIND_EXECUTION {
        return Err(VerifyError::ReceiptKind(h.receipt_kind));
    }
    if h.protocol_version != PROTOCOL_VERSION {
        return Err(VerifyError::ProtocolVersion(h.protocol_version));
    }
    if h.verifier_version != VERIFIER_VERSION {
        return Err(VerifyError::VerifierVersion(h.verifier_version));
    }
    if h.suite_id != SUITE_ID {
        return Err(VerifyError::Suite(h.suite_id));
    }
    if h.program_id != program_id() {
        return Err(VerifyError::ProgramIdentity);
    }
    Ok(())
}

fn verify_expected(receipt: &Receipt, expected: &ExpectedContext) -> Result<(), VerifyError> {
    let h = &receipt.header;
    let checks = [
        (
            h.protocol_version == expected.protocol_version,
            "protocol version",
        ),
        (
            h.verifier_version == expected.verifier_version,
            "verifier version",
        ),
        (h.program_id == expected.program_id, "program identity"),
        (
            h.pre_state_root == expected.pre_state_root,
            "pre-state root",
        ),
        (h.block_id == expected.block_id, "canonical block"),
        (
            h.post_state_root == expected.post_state_root,
            "post-state root",
        ),
    ];
    for (ok, name) in checks {
        if !ok {
            return Err(VerifyError::ContextMismatch(name));
        }
    }
    Ok(())
}
