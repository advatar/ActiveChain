//! Crash-atomic bounded proof-job and one-time prover-reward state.

use super::{
    ExecutionProofVerifier, FinalizedBlock, FinalizedBlockHeader, ProofPublicInputs,
    VerifiedExecutionProof, invalid_data, write_atomic,
};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_devnet_kernel::{BlockReceipt, ChainState};
use activechain_protocol_types::{Digest384, PrincipalId};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{collections::BTreeMap, path::Path};

const MAX_PROOF_JOBS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofJobStatus {
    Queued,
    Dispatched,
    Accepted,
    Finalized,
}
impl CanonicalEncode for ProofJobStatus {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        (*self as u8).encode(e)
    }
}
impl CanonicalDecode for ProofJobStatus {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match u8::decode(d)? {
            0 => Ok(Self::Queued),
            1 => Ok(Self::Dispatched),
            2 => Ok(Self::Accepted),
            3 => Ok(Self::Finalized),
            tag => Err(DecodeError::InvalidEnumTag { type_name: "ProofJobStatus", tag }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProofJob {
    inputs: ProofPublicInputs,
    status: ProofJobStatus,
    attempts: u8,
    deadline: u64,
    proof_statement: Option<Digest384>,
    prover: Option<PrincipalId>,
    rewarded: bool,
    finalized_block: Option<Digest384>,
}
impl CanonicalEncode for ProofJob {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.inputs.encode(e)?;
        self.status.encode(e)?;
        self.attempts.encode(e)?;
        self.deadline.encode(e)?;
        encode_option_digest(e, self.proof_statement)?;
        encode_option_principal(e, self.prover)?;
        u8::from(self.rewarded).encode(e)?;
        encode_option_digest(e, self.finalized_block)
    }
}
impl CanonicalDecode for ProofJob {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            inputs: ProofPublicInputs::decode(d)?,
            status: ProofJobStatus::decode(d)?,
            attempts: u8::decode(d)?,
            deadline: u64::decode(d)?,
            proof_statement: decode_option_digest(d)?,
            prover: decode_option_principal(d)?,
            rewarded: match u8::decode(d)? {
                0 => false,
                1 => true,
                _ => return Err(DecodeError::InvalidValue("invalid reward flag")),
            },
            finalized_block: decode_option_digest(d)?,
        };
        let pending = matches!(value.status, ProofJobStatus::Queued | ProofJobStatus::Dispatched);
        if value.attempts > 3
            || pending
                && (value.proof_statement.is_some() || value.prover.is_some() || value.rewarded)
            || !pending && (value.proof_statement.is_none() || value.prover.is_none())
            || value.rewarded && value.status != ProofJobStatus::Finalized
            || (value.status == ProofJobStatus::Finalized) != value.finalized_block.is_some()
        {
            return Err(DecodeError::InvalidValue("inconsistent proof job"));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DurableProofPipeline {
    jobs: BTreeMap<Digest384, ProofJob>,
    finalized_height: u64,
}
impl DurableProofPipeline {
    pub fn job_id(inputs: &ProofPublicInputs) -> Result<Digest384, ProofPipelineError> {
        let bytes = encode_envelope(inputs).map_err(|_| ProofPipelineError::Encoding)?;
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-PROOF-JOB-V1");
        h.update(&bytes);
        let mut out = [0; 48];
        h.finalize_xof().read(&mut out);
        Ok(Digest384::new(out))
    }
    pub fn enqueue(&mut self, inputs: ProofPublicInputs) -> Result<Digest384, ProofPipelineError> {
        if self.jobs.len() >= MAX_PROOF_JOBS {
            return Err(ProofPipelineError::Backpressure);
        }
        let id = Self::job_id(&inputs)?;
        if self.jobs.contains_key(&id) {
            return Err(ProofPipelineError::Replay);
        }
        self.jobs.insert(
            id,
            ProofJob {
                inputs,
                status: ProofJobStatus::Queued,
                attempts: 0,
                deadline: 0,
                proof_statement: None,
                prover: None,
                rewarded: false,
                finalized_block: None,
            },
        );
        Ok(id)
    }
    pub fn dispatch(
        &mut self,
        id: Digest384,
        now: u64,
        timeout: u64,
    ) -> Result<(), ProofPipelineError> {
        let job = self.jobs.get_mut(&id).ok_or(ProofPipelineError::Unknown)?;
        if !matches!(job.status, ProofJobStatus::Queued | ProofJobStatus::Dispatched)
            || job.status == ProofJobStatus::Dispatched && now <= job.deadline
        {
            return Err(ProofPipelineError::State);
        }
        job.attempts = job
            .attempts
            .checked_add(1)
            .filter(|v| *v <= 3)
            .ok_or(ProofPipelineError::RetriesExhausted)?;
        job.deadline = now.checked_add(timeout).ok_or(ProofPipelineError::Overflow)?;
        job.status = ProofJobStatus::Dispatched;
        Ok(())
    }
    pub fn accept<V: ExecutionProofVerifier>(
        &mut self,
        id: Digest384,
        proof: &VerifiedExecutionProof,
        verifier: &V,
    ) -> Result<(), ProofPipelineError> {
        let job = self.jobs.get_mut(&id).ok_or(ProofPipelineError::Unknown)?;
        if job.status != ProofJobStatus::Dispatched || job.inputs != proof.inputs {
            return Err(ProofPipelineError::CrossJob);
        }
        let statement = proof.statement_commitment().map_err(|_| ProofPipelineError::Encoding)?;
        if proof.proof_bytes.is_empty()
            || !verifier.verify(proof.proof_system, statement, &proof.proof_bytes)
        {
            return Err(ProofPipelineError::InvalidProof);
        }
        job.status = ProofJobStatus::Accepted;
        job.proof_statement = Some(statement);
        job.prover = Some(proof.prover);
        Ok(())
    }
    pub fn finalize(
        &mut self,
        id: Digest384,
        height: u64,
        block_digest: Digest384,
    ) -> Result<(), ProofPipelineError> {
        if height != self.finalized_height.checked_add(1).ok_or(ProofPipelineError::Overflow)? {
            return Err(ProofPipelineError::Order);
        }
        let job = self.jobs.get_mut(&id).ok_or(ProofPipelineError::Unknown)?;
        if job.status != ProofJobStatus::Accepted {
            return Err(ProofPipelineError::State);
        }
        job.status = ProofJobStatus::Finalized;
        job.finalized_block = Some(block_digest);
        self.finalized_height = height;
        Ok(())
    }
    pub fn claim_reward(&mut self, id: Digest384) -> Result<PrincipalId, ProofPipelineError> {
        let job = self.jobs.get_mut(&id).ok_or(ProofPipelineError::Unknown)?;
        if job.status != ProofJobStatus::Finalized || job.rewarded {
            return Err(ProofPipelineError::Replay);
        }
        job.rewarded = true;
        job.prover.ok_or(ProofPipelineError::State)
    }
    /// Publishes executed chain state, fee/supply result, DA/proof/header metadata, proof finality,
    /// and reward replay state in one fsync+rename snapshot.
    pub fn commit_finalized(
        &mut self,
        id: Digest384,
        block: &FinalizedBlock,
        path: &Path,
    ) -> Result<(), ProofPipelineError> {
        let mut next = self.clone();
        next.finalize(id, block.header.inputs.height(), block.block_digest)?;
        let snapshot = DurableFinalizedState {
            pipeline: next.clone(),
            chain_state: block.next_state.clone(),
            header: block.header,
            receipt: block.receipt.clone(),
            block_digest: block.block_digest,
            proof_statement: block.proof_statement_commitment,
            post_supply: block.post_supply,
        };
        snapshot.save(path).map_err(|_| ProofPipelineError::Persistence)?;
        *self = next;
        Ok(())
    }
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut bytes =
            encode_envelope(self).map_err(|_| invalid_data("proof pipeline encoding failed"))?;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-PROOF-PIPELINE-SNAPSHOT-V1");
        hasher.update(&bytes);
        let mut tag = [0_u8; 32];
        hasher.finalize_xof().read(&mut tag);
        bytes.extend_from_slice(&tag);
        write_atomic(path, &bytes)
    }
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 32 {
            return Err(invalid_data("proof pipeline snapshot invalid"));
        }
        let body_len = bytes.len() - 32;
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-PROOF-PIPELINE-SNAPSHOT-V1");
        hasher.update(&bytes[..body_len]);
        let mut tag = [0_u8; 32];
        hasher.finalize_xof().read(&mut tag);
        if tag != bytes[body_len..] {
            return Err(invalid_data("proof pipeline snapshot corrupt"));
        }
        decode_envelope(&bytes[..body_len])
            .map_err(|_| invalid_data("proof pipeline snapshot invalid"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableFinalizedState {
    pub pipeline: DurableProofPipeline,
    pub chain_state: ChainState,
    pub header: FinalizedBlockHeader,
    pub receipt: BlockReceipt,
    pub block_digest: Digest384,
    pub proof_statement: Digest384,
    pub post_supply: u128,
}
impl DurableFinalizedState {
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut bytes =
            encode_envelope(self).map_err(|_| invalid_data("finalized state encoding failed"))?;
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-DURABLE-FINALIZED-STATE-V1");
        h.update(&bytes);
        let mut tag = [0_u8; 32];
        h.finalize_xof().read(&mut tag);
        bytes.extend_from_slice(&tag);
        write_atomic(path, &bytes)
    }
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 32 {
            return Err(invalid_data("finalized state snapshot invalid"));
        }
        let body = bytes.len() - 32;
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-DURABLE-FINALIZED-STATE-V1");
        h.update(&bytes[..body]);
        let mut tag = [0_u8; 32];
        h.finalize_xof().read(&mut tag);
        if tag != bytes[body..] {
            return Err(invalid_data("finalized state snapshot corrupt"));
        }
        decode_envelope(&bytes[..body])
            .map_err(|_| invalid_data("finalized state snapshot invalid"))
    }
}
impl CanonicalEncode for DurableFinalizedState {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.pipeline.encode(e)?;
        self.chain_state.encode(e)?;
        self.header.encode(e)?;
        self.receipt.encode(e)?;
        self.block_digest.encode(e)?;
        self.proof_statement.encode(e)?;
        self.post_supply.encode(e)
    }
}
impl CanonicalDecode for DurableFinalizedState {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            pipeline: DurableProofPipeline::decode(d)?,
            chain_state: ChainState::decode(d)?,
            header: FinalizedBlockHeader::decode(d)?,
            receipt: BlockReceipt::decode(d)?,
            block_digest: Digest384::decode(d)?,
            proof_statement: Digest384::decode(d)?,
            post_supply: u128::decode(d)?,
        };
        if value
            .header
            .digest()
            .map_err(|_| DecodeError::InvalidValue("invalid finalized header"))?
            != value.block_digest
            || value.header.proof_statement_commitment != value.proof_statement
            || value.chain_state.height() != value.receipt.height()
            || value.receipt.post_state() != value.header.inputs.post_state()
        {
            return Err(DecodeError::InvalidValue("inconsistent finalized state snapshot"));
        }
        Ok(value)
    }
}
impl CanonicalType for DurableFinalizedState {
    const TYPE_TAG: u16 = 0x007c;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = DurableProofPipeline::MAX_ENCODED_LEN
        + ChainState::MAX_ENCODED_LEN
        + FinalizedBlockHeader::MAX_ENCODED_LEN
        + BlockReceipt::MAX_ENCODED_LEN
        + 48
        + 48
        + 16;
}
impl CanonicalEncode for DurableProofPipeline {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.finalized_height.encode(e)?;
        e.write_length(self.jobs.len(), MAX_PROOF_JOBS)?;
        for (id, job) in &self.jobs {
            id.encode(e)?;
            job.encode(e)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for DurableProofPipeline {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let finalized_height = u64::decode(d)?;
        let count = d.read_length(MAX_PROOF_JOBS)?;
        let mut jobs = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let id = Digest384::decode(d)?;
            if previous.is_some_and(|p| p >= id) {
                return Err(DecodeError::InvalidValue("unordered proof jobs"));
            }
            let job = ProofJob::decode(d)?;
            if Self::job_id(&job.inputs)
                .map_err(|_| DecodeError::InvalidValue("invalid proof job id"))?
                != id
            {
                return Err(DecodeError::InvalidValue("mismatched proof job id"));
            }
            jobs.insert(id, job);
            previous = Some(id);
        }
        Ok(Self { jobs, finalized_height })
    }
}
impl CanonicalType for DurableProofPipeline {
    const TYPE_TAG: u16 = 0x007a;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 8
        + 2
        + MAX_PROOF_JOBS
            * (48 + ProofPublicInputs::MAX_ENCODED_LEN + 1 + 1 + 8 + 1 + 48 + 1 + 48 + 1 + 1 + 48);
}

fn encode_option_digest(e: &mut Encoder, value: Option<Digest384>) -> Result<(), EncodeError> {
    match value {
        None => 0_u8.encode(e),
        Some(value) => {
            1_u8.encode(e)?;
            value.encode(e)
        }
    }
}
fn decode_option_digest(d: &mut Decoder<'_>) -> Result<Option<Digest384>, DecodeError> {
    match u8::decode(d)? {
        0 => Ok(None),
        1 => Ok(Some(Digest384::decode(d)?)),
        _ => Err(DecodeError::InvalidValue("invalid optional digest")),
    }
}
fn encode_option_principal(e: &mut Encoder, value: Option<PrincipalId>) -> Result<(), EncodeError> {
    match value {
        None => 0_u8.encode(e),
        Some(value) => {
            1_u8.encode(e)?;
            value.encode(e)
        }
    }
}
fn decode_option_principal(d: &mut Decoder<'_>) -> Result<Option<PrincipalId>, DecodeError> {
    match u8::decode(d)? {
        0 => Ok(None),
        1 => Ok(Some(PrincipalId::decode(d)?)),
        _ => Err(DecodeError::InvalidValue("invalid optional principal")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofPipelineError {
    Encoding,
    Backpressure,
    Replay,
    Unknown,
    State,
    RetriesExhausted,
    Overflow,
    CrossJob,
    InvalidProof,
    Order,
    Persistence,
}
