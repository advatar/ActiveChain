#![forbid(unsafe_code)]

//! Bounded data-availability shards for the first PQ testnet rehearsal.

use reed_solomon_erasure::galois_8::ReedSolomon;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const MAX_SHARD_BYTES: usize = 1 << 20;
pub const MAX_SHARDS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardCommitment([u8; 48]);
impl ShardCommitment {
    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailabilityBatch {
    data_shards: usize,
    parity_shards: usize,
    shard_size: usize,
    shards: Vec<Vec<u8>>,
    commitments: Vec<ShardCommitment>,
}
impl AvailabilityBatch {
    pub fn encode(
        payload: &[u8],
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<Self, AvailabilityError> {
        if payload.is_empty()
            || data_shards == 0
            || parity_shards == 0
            || data_shards + parity_shards > MAX_SHARDS
        {
            return Err(AvailabilityError::Bounds);
        }
        let shard_size = payload.len().div_ceil(data_shards);
        if shard_size > MAX_SHARD_BYTES {
            return Err(AvailabilityError::Bounds);
        }
        let total = data_shards + parity_shards;
        let mut shards = vec![vec![0_u8; shard_size]; total];
        for (index, byte) in payload.iter().enumerate() {
            shards[index / shard_size][index % shard_size] = *byte;
        }
        ReedSolomon::new(data_shards, parity_shards)
            .map_err(|_| AvailabilityError::InvalidLayout)?
            .encode(&mut shards)
            .map_err(|_| AvailabilityError::CodingFailed)?;
        let commitments =
            shards.iter().enumerate().map(|(index, shard)| commitment(index, shard)).collect();
        Ok(Self { data_shards, parity_shards, shard_size, shards, commitments })
    }
    pub fn shards(&self) -> &[Vec<u8>] {
        &self.shards
    }
    pub fn commitments(&self) -> &[ShardCommitment] {
        &self.commitments
    }
    pub fn sample(&self, seed: &[u8; 48], count: usize) -> Result<Vec<usize>, AvailabilityError> {
        if count == 0 || count > self.shards.len() {
            return Err(AvailabilityError::Bounds);
        }
        let mut reader = Shake256::default();
        reader.update(b"ACTIVECHAIN-DA-SAMPLE-V1");
        reader.update(seed);
        let mut output = vec![0_u8; count * 8];
        reader.finalize_xof().read(&mut output);
        let mut indices = Vec::with_capacity(count);
        for chunk in output.chunks_exact(8) {
            indices
                .push(u64::from_be_bytes(chunk.try_into().unwrap()) as usize % self.shards.len());
        }
        indices.sort_unstable();
        indices.dedup();
        if indices.len() != count {
            return Err(AvailabilityError::SampleCollision);
        }
        Ok(indices)
    }
    pub fn reconstruct(&self, missing: &[usize]) -> Result<Vec<Vec<u8>>, AvailabilityError> {
        if missing.iter().any(|index| *index >= self.shards.len())
            || missing.len() > self.parity_shards
        {
            return Err(AvailabilityError::TooManyMissing);
        }
        if (0..self.shards.len()).any(|index| {
            !missing.contains(&index)
                && commitment(index, &self.shards[index]) != self.commitments[index]
        }) {
            return Err(AvailabilityError::CommitmentMismatch);
        }
        let mut shards: Vec<Option<Vec<u8>>> = self.shards.iter().cloned().map(Some).collect();
        for index in missing {
            shards[*index] = None;
        }
        ReedSolomon::new(self.data_shards, self.parity_shards)
            .map_err(|_| AvailabilityError::InvalidLayout)?
            .reconstruct(&mut shards)
            .map_err(|_| AvailabilityError::ReconstructionFailed)?;
        let restored: Vec<Vec<u8>> = shards
            .into_iter()
            .map(|shard| shard.ok_or(AvailabilityError::ReconstructionFailed))
            .collect::<Result<_, _>>()?;
        for (index, shard) in restored.iter().enumerate() {
            if commitment(index, shard) != self.commitments[index] {
                return Err(AvailabilityError::CommitmentMismatch);
            }
        }
        Ok(restored)
    }
}
fn commitment(index: usize, shard: &[u8]) -> ShardCommitment {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-DA-SHARD-V1");
    hasher.update(&(index as u32).to_be_bytes());
    hasher.update(&(shard.len() as u32).to_be_bytes());
    hasher.update(shard);
    let mut output = [0_u8; 48];
    hasher.finalize_xof().read(&mut output);
    ShardCommitment(output)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityError {
    Bounds,
    InvalidLayout,
    CodingFailed,
    TooManyMissing,
    ReconstructionFailed,
    CommitmentMismatch,
    SampleCollision,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shards_reconstruct_after_parity_loss_and_commitments_detect_tampering() {
        let batch = AvailabilityBatch::encode(b"activechain-pq-availability", 3, 2).unwrap();
        let restored = batch.reconstruct(&[1, 4]).unwrap();
        assert_eq!(restored, batch.shards);
        let mut tampered = batch.clone();
        tampered.shards[0][0] ^= 1;
        assert_eq!(tampered.reconstruct(&[1]), Err(AvailabilityError::CommitmentMismatch));
    }
    #[test]
    fn sampling_is_deterministic_and_bounded() {
        let batch = AvailabilityBatch::encode(b"sample", 2, 2).unwrap();
        assert_eq!(batch.sample(&[9; 48], 2), batch.sample(&[9; 48], 2));
        assert_eq!(batch.sample(&[9; 48], 0), Err(AvailabilityError::Bounds));
    }
}
