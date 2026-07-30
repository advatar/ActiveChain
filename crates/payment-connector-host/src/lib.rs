#![forbid(unsafe_code)]

//! Durable, fail-closed observation state for out-of-consensus payment connectors.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_payment_types::{PaymentValidationError, ProviderObservationV1};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{fs::File, io::Write, path::Path};

mod simulator;

pub use simulator::{
    ConnectorContract, ConnectorError, DeterministicConnector, SimulatorRequest, SimulatorScenario,
};

const MAX_OBSERVATIONS: usize = 65_535;
const SNAPSHOT_TAG_LENGTH: usize = 48;
const SNAPSHOT_DOMAIN: &[u8] = b"ACTIVECHAIN-ACTIVEBRIDGE-JOURNAL-V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    InvalidObservation,
    Capacity,
    Persistence,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectorJournalV1 {
    observations: Vec<ProviderObservationV1>,
}

impl ConnectorJournalV1 {
    #[must_use]
    pub fn observations(&self) -> &[ProviderObservationV1] {
        &self.observations
    }

    /// Applies exact replay without mutation or atomically advances one attempt.
    pub fn record(&mut self, observation: ProviderObservationV1) -> Result<bool, JournalError> {
        match self
            .observations
            .binary_search_by_key(&observation.attempt(), ProviderObservationV1::attempt)
        {
            Ok(index) => {
                let changed = self.observations[index]
                    .compare_successor(&observation)
                    .map_err(map_validation)?;
                if changed {
                    self.observations[index] = observation;
                }
                Ok(changed)
            }
            Err(index) => {
                if self.observations.len() == MAX_OBSERVATIONS || observation.sequence() != 1 {
                    return Err(if self.observations.len() == MAX_OBSERVATIONS {
                        JournalError::Capacity
                    } else {
                        JournalError::InvalidObservation
                    });
                }
                self.observations.insert(index, observation);
                Ok(true)
            }
        }
    }

    pub fn record_durable(
        &mut self,
        observation: ProviderObservationV1,
        path: &Path,
    ) -> Result<bool, JournalError> {
        let mut next = self.clone();
        let changed = next.record(observation)?;
        if changed {
            next.save_atomic(path)?;
            *self = next;
        }
        Ok(changed)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), JournalError> {
        let body = encode_envelope(self).map_err(|_| JournalError::Persistence)?;
        let tag = snapshot_tag(&body);
        let parent = path.parent().ok_or(JournalError::Persistence)?;
        std::fs::create_dir_all(parent).map_err(|_| JournalError::Persistence)?;
        let name = path.file_name().ok_or(JournalError::Persistence)?.to_string_lossy();
        let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
        let result = (|| {
            let mut file = File::create(&temporary).map_err(|_| JournalError::Persistence)?;
            file.write_all(&body)
                .and_then(|_| file.write_all(&tag))
                .and_then(|_| file.sync_all())
                .map_err(|_| JournalError::Persistence)?;
            std::fs::rename(&temporary, path).map_err(|_| JournalError::Persistence)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| JournalError::Persistence)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    pub fn load(path: &Path) -> Result<Self, JournalError> {
        let bytes = std::fs::read(path).map_err(|_| JournalError::Persistence)?;
        if bytes.len() < SNAPSHOT_TAG_LENGTH {
            return Err(JournalError::Persistence);
        }
        let body_length = bytes.len() - SNAPSHOT_TAG_LENGTH;
        if snapshot_tag(&bytes[..body_length]) != bytes[body_length..] {
            return Err(JournalError::Persistence);
        }
        decode_envelope(&bytes[..body_length]).map_err(|_| JournalError::Persistence)
    }
}

impl CanonicalEncode for ConnectorJournalV1 {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        encoder.write_length(self.observations.len(), MAX_OBSERVATIONS)?;
        for observation in &self.observations {
            observation.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for ConnectorJournalV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.read_length(MAX_OBSERVATIONS)?;
        let mut observations = Vec::with_capacity(count);
        for _ in 0..count {
            let observation = ProviderObservationV1::decode(decoder)?;
            if observation.sequence() == 0
                || observations.last().is_some_and(|previous: &ProviderObservationV1| {
                    previous.attempt() >= observation.attempt()
                })
            {
                return Err(DecodeError::InvalidValue(
                    "connector observations are not canonically ordered",
                ));
            }
            observations.push(observation);
        }
        Ok(Self { observations })
    }
}

impl CanonicalType for ConnectorJournalV1 {
    const TYPE_TAG: u16 = 0x0142;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 3 + MAX_OBSERVATIONS * ProviderObservationV1::MAX_ENCODED_LEN;
}

fn map_validation(_: PaymentValidationError) -> JournalError {
    JournalError::InvalidObservation
}

fn snapshot_tag(bytes: &[u8]) -> [u8; SNAPSHOT_TAG_LENGTH] {
    let mut hasher = Shake256::default();
    hasher.update(SNAPSHOT_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    let mut output = [0; SNAPSHOT_TAG_LENGTH];
    hasher.finalize_xof().read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_payment_types::{
        AssetAmountV1, ConnectorId, EvidenceClass, PaymentAttemptId, PaymentIntentId,
        ProviderOperationState,
    };
    use activechain_protocol_types::{AssetId, ChainId, Digest384};
    use std::path::PathBuf;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn observation(attempt: u8, sequence: u64, payload: u8) -> ProviderObservationV1 {
        ProviderObservationV1::new(
            ChainId::new(digest(1)),
            ConnectorId::new(digest(2)).unwrap(),
            PaymentAttemptId::new(digest(attempt)).unwrap(),
            PaymentIntentId::new(digest(4)).unwrap(),
            digest(5),
            digest(6),
            sequence,
            ProviderOperationState::Pending,
            AssetAmountV1::new(AssetId::new(digest(7)), 100).unwrap(),
            100,
            100 + sequence,
            EvidenceClass::ProviderSigned,
            digest(payload),
        )
        .unwrap()
    }

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "activebridge-{name}-{}-{}.bin",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn exact_replay_is_noop_and_gaps_fail_closed() {
        let mut journal = ConnectorJournalV1::default();
        let first = observation(10, 1, 20);
        assert_eq!(journal.record(first.clone()), Ok(true));
        assert_eq!(journal.record(first), Ok(false));
        assert_eq!(journal.record(observation(10, 3, 22)), Err(JournalError::InvalidObservation));
        assert_eq!(journal.observations()[0].sequence(), 1);
    }

    #[test]
    fn durable_advance_survives_restart_and_corruption_is_rejected() {
        let path = path("restart");
        let _ = std::fs::remove_file(&path);
        let mut journal = ConnectorJournalV1::default();
        assert_eq!(journal.record_durable(observation(10, 1, 20), &path), Ok(true));
        assert_eq!(ConnectorJournalV1::load(&path).unwrap(), journal);
        assert_eq!(journal.record_durable(observation(10, 2, 21), &path), Ok(true));
        assert_eq!(ConnectorJournalV1::load(&path).unwrap(), journal);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[8] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(ConnectorJournalV1::load(&path), Err(JournalError::Persistence));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_persistence_does_not_mutate_memory() {
        let directory = path("directory");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut journal = ConnectorJournalV1::default();
        assert_eq!(
            journal.record_durable(observation(10, 1, 20), &directory),
            Err(JournalError::Persistence)
        );
        assert!(journal.observations().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
