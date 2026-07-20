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
    payload_len: usize,
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
        Ok(Self {
            data_shards,
            parity_shards,
            shard_size,
            payload_len: payload.len(),
            shards,
            commitments,
        })
    }
    pub fn shards(&self) -> &[Vec<u8>] {
        &self.shards
    }
    pub fn commitments(&self) -> &[ShardCommitment] {
        &self.commitments
    }
    pub fn payload_commitment(&self) -> Result<ShardCommitment, AvailabilityError> {
        let payload = self.reconstruct_payload(&[])?;
        Ok(payload_commitment(&payload))
    }
    pub fn serialize(&self) -> Result<Vec<u8>, AvailabilityError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ACDA1");
        bytes.extend_from_slice(&(self.data_shards as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.parity_shards as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.shard_size as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.payload_len as u32).to_be_bytes());
        for (shard, commitment) in self.shards.iter().zip(&self.commitments) {
            bytes.extend_from_slice(&(shard.len() as u32).to_be_bytes());
            bytes.extend_from_slice(shard);
            bytes.extend_from_slice(commitment.as_bytes());
        }
        Ok(bytes)
    }
    pub fn deserialize(bytes: &[u8]) -> Result<Self, AvailabilityError> {
        if bytes.len() < 17 || &bytes[..5] != b"ACDA1" {
            return Err(AvailabilityError::InvalidLayout);
        }
        let data_shards = u16::from_be_bytes(bytes[5..7].try_into().unwrap()) as usize;
        let parity_shards = u16::from_be_bytes(bytes[7..9].try_into().unwrap()) as usize;
        let shard_size = u32::from_be_bytes(bytes[9..13].try_into().unwrap()) as usize;
        let payload_len = u32::from_be_bytes(bytes[13..17].try_into().unwrap()) as usize;
        if data_shards == 0
            || parity_shards == 0
            || data_shards + parity_shards > MAX_SHARDS
            || shard_size > MAX_SHARD_BYTES
            || payload_len == 0
            || payload_len > data_shards * shard_size
        {
            return Err(AvailabilityError::InvalidLayout);
        }
        let mut offset = 17;
        let mut shards = Vec::with_capacity(data_shards + parity_shards);
        let mut commitments = Vec::with_capacity(data_shards + parity_shards);
        for _ in 0..data_shards + parity_shards {
            if bytes.len() < offset + 4 {
                return Err(AvailabilityError::InvalidLayout);
            }
            let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if length != shard_size || bytes.len() < offset + length + 48 {
                return Err(AvailabilityError::InvalidLayout);
            }
            let shard = bytes[offset..offset + length].to_vec();
            offset += length;
            let field_commitment = ShardCommitment(bytes[offset..offset + 48].try_into().unwrap());
            offset += 48;
            if commitment(shards.len(), &shard) != field_commitment {
                return Err(AvailabilityError::CommitmentMismatch);
            }
            shards.push(shard);
            commitments.push(field_commitment);
        }
        if offset != bytes.len() {
            return Err(AvailabilityError::InvalidLayout);
        }
        Ok(Self { data_shards, parity_shards, shard_size, payload_len, shards, commitments })
    }
    pub fn reconstruct_payload(&self, missing: &[usize]) -> Result<Vec<u8>, AvailabilityError> {
        let shards = self.reconstruct(missing)?;
        let mut payload = Vec::with_capacity(self.payload_len);
        for shard in shards.iter().take(self.data_shards) {
            payload.extend_from_slice(shard);
        }
        payload.truncate(self.payload_len);
        Ok(payload)
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

fn payload_commitment(payload: &[u8]) -> ShardCommitment {
    let mut output = [0_u8; 48];
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-DA-PAYLOAD-V1");
    hasher.update(payload);
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
    #[test]
    fn serialized_batches_reconstruct_payload_after_distribution() {
        let batch = AvailabilityBatch::encode(b"distributed snapshot payload", 3, 2).unwrap();
        let restored = AvailabilityBatch::deserialize(&batch.serialize().unwrap()).unwrap();
        assert_eq!(restored.reconstruct_payload(&[0, 3]).unwrap(), b"distributed snapshot payload");
        assert_eq!(restored.payload_commitment().unwrap(), batch.payload_commitment().unwrap());
    }
}
