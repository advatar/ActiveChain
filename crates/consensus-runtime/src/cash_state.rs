use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
};
use activechain_cash_kernel::{CoinCellSet, authenticated_coin_cell_root};
use activechain_protocol_types::Digest384;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::path::Path;

/// Authenticated finalized cash state handed from execution to RPC indexing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedCashSnapshot {
    pub chain_genesis: Digest384,
    pub finalized_height: u64,
    pub cash_cell_root: Digest384,
    pub cells: CoinCellSet,
}

impl FinalizedCashSnapshot {
    pub fn new(
        chain_genesis: Digest384,
        finalized_height: u64,
        cells: CoinCellSet,
    ) -> Result<Self, &'static str> {
        if chain_genesis == Digest384::ZERO {
            return Err("zero chain genesis");
        }
        let cash_cell_root = authenticated_coin_cell_root(&cells)
            .map_err(|_| "invalid cash cell set")?
            .into_digest();
        Ok(Self { chain_genesis, finalized_height, cash_cell_root, cells })
    }

    /// Constructs an execution snapshot only after the finalized certificate
    /// authenticates the resulting cash root and height.
    pub fn new_verified(
        chain_genesis: Digest384,
        finalized_height: u64,
        cells: CoinCellSet,
        finality: &[u8],
    ) -> Result<Self, &'static str> {
        let snapshot = Self::new(chain_genesis, finalized_height, cells)?;
        snapshot.verify_against_finality(finality)?;
        Ok(snapshot)
    }

    pub fn verify(&self) -> Result<(), &'static str> {
        if self.chain_genesis == Digest384::ZERO {
            return Err("zero chain genesis");
        }
        if authenticated_coin_cell_root(&self.cells)
            .map_err(|_| "invalid cash cell set")?
            .into_digest()
            != self.cash_cell_root
        {
            return Err("cash cell root mismatch");
        }
        Ok(())
    }

    /// Verifies that this persisted cash state is the exact cash root carried
    /// by a finalized certificate for the same chain and height.
    pub fn verify_against_finality(&self, finality: &[u8]) -> Result<(), &'static str> {
        self.verify()?;
        let bundle = activechain_verifier_api::verify_finality_bundle_with_chain_genesis(
            finality,
            self.chain_genesis,
        )
        .map_err(|_| "invalid finality bundle")?;
        if bundle.header().inputs.height != self.finalized_height {
            return Err("cash snapshot height differs from finality");
        }
        if bundle.header().inputs.cash_cell_root != self.cash_cell_root {
            return Err("cash snapshot root differs from finality");
        }
        Ok(())
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let body = activechain_canonical_codec::encode_envelope(self)
            .map_err(|_| std::io::Error::other("cash snapshot encoding failed"))?;
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-FINALIZED-CASH-SNAPSHOT-V1");
        h.update(&body);
        let mut tag = [0_u8; 32];
        h.finalize_xof().read(&mut tag);
        let mut bytes = body;
        bytes.extend_from_slice(&tag);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(tmp, path)
    }

    /// Persist the cash snapshot together with the exact finalized certificate
    /// that authenticated its height and root. Restart callers must use
    /// `load_verified` before publishing any records.
    pub fn save_with_finality(&self, path: &Path, finality: &[u8]) -> std::io::Result<()> {
        self.verify_against_finality(finality).map_err(std::io::Error::other)?;
        let persisted =
            PersistedFinalizedCash { snapshot: self.clone(), finality: finality.to_vec() };
        let body = activechain_canonical_codec::encode_envelope(&persisted)
            .map_err(|_| std::io::Error::other("cash persistence encoding failed"))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(tmp, path)
    }

    pub fn load_verified(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let persisted: PersistedFinalizedCash =
            activechain_canonical_codec::decode_envelope(&bytes)
                .map_err(|_| std::io::Error::other("cash persistence malformed"))?;
        persisted
            .snapshot
            .verify_against_finality(&persisted.finality)
            .map_err(std::io::Error::other)?;
        Ok(persisted.snapshot)
    }

    /// Loads the canonical envelope materialized by the finalized-round journal.
    ///
    /// This representation deliberately does not embed finality: callers at publication
    /// boundaries must verify it against the separately journaled finality bundle.
    pub fn load_canonical(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        activechain_canonical_codec::decode_envelope(&bytes)
            .map_err(|_| std::io::Error::other("canonical cash snapshot malformed"))
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 32 {
            return Err(std::io::Error::other("cash snapshot truncated"));
        }
        let split = bytes.len() - 32;
        let body = &bytes[..split];
        let mut h = Shake256::default();
        h.update(b"ACTIVECHAIN-FINALIZED-CASH-SNAPSHOT-V1");
        h.update(body);
        let mut tag = [0_u8; 32];
        h.finalize_xof().read(&mut tag);
        if tag != bytes[split..] {
            return Err(std::io::Error::other("cash snapshot checksum mismatch"));
        }
        activechain_canonical_codec::decode_envelope(body)
            .map_err(|_| std::io::Error::other("cash snapshot malformed"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersistedFinalizedCash {
    snapshot: FinalizedCashSnapshot,
    finality: Vec<u8>,
}

impl CanonicalEncode for PersistedFinalizedCash {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.snapshot.encode(e)?;
        e.write_bytes(&self.finality, 16 * 1024)
    }
}
impl CanonicalDecode for PersistedFinalizedCash {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            snapshot: FinalizedCashSnapshot::decode(d)?,
            finality: d.read_bytes(16 * 1024)?.to_vec(),
        };
        if value.finality.is_empty() {
            return Err(DecodeError::InvalidValue("empty finality evidence"));
        }
        Ok(value)
    }
}
impl CanonicalType for PersistedFinalizedCash {
    const TYPE_TAG: u16 = 0x0103;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = FinalizedCashSnapshot::MAX_ENCODED_LEN + 16 * 1024;
}

impl CanonicalEncode for FinalizedCashSnapshot {
    fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_genesis.encode(e)?;
        self.finalized_height.encode(e)?;
        self.cash_cell_root.encode(e)?;
        self.cells.encode(e)
    }
}
impl CanonicalDecode for FinalizedCashSnapshot {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            chain_genesis: Digest384::decode(d)?,
            finalized_height: u64::decode(d)?,
            cash_cell_root: Digest384::decode(d)?,
            cells: CoinCellSet::decode(d)?,
        };
        value.verify().map_err(DecodeError::InvalidValue)?;
        Ok(value)
    }
}
impl CanonicalType for FinalizedCashSnapshot {
    const TYPE_TAG: u16 = 0x008e;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 8 + 48 + CoinCellSet::MAX_ENCODED_LEN;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_finality_binding_rejects_malformed_evidence() {
        let cells = CoinCellSet::new(Vec::new()).unwrap();
        let snapshot = FinalizedCashSnapshot::new(Digest384::new([1; 48]), 7, cells).unwrap();
        assert_eq!(snapshot.verify_against_finality(&[1, 2, 3]), Err("invalid finality bundle"));
    }

    #[test]
    fn persisted_cash_rejects_empty_finality_evidence() {
        let cells = CoinCellSet::new(Vec::new()).unwrap();
        let snapshot = FinalizedCashSnapshot::new(Digest384::new([1; 48]), 7, cells).unwrap();
        let persisted = PersistedFinalizedCash { snapshot, finality: Vec::new() };
        let encoded = activechain_canonical_codec::encode_envelope(&persisted).unwrap();
        assert!(
            activechain_canonical_codec::decode_envelope::<PersistedFinalizedCash>(&encoded)
                .is_err()
        );
    }

    #[test]
    fn canonical_snapshot_loader_accepts_journal_format_and_rejects_trailing_data() {
        let cells = CoinCellSet::new(Vec::new()).unwrap();
        let snapshot = FinalizedCashSnapshot::new(Digest384::new([1; 48]), 7, cells).unwrap();
        let path = std::env::temp_dir().join(format!(
            "activechain-canonical-cash-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let encoded = activechain_canonical_codec::encode_envelope(&snapshot).unwrap();
        std::fs::write(&path, &encoded).unwrap();
        assert_eq!(FinalizedCashSnapshot::load_canonical(&path).unwrap(), snapshot);
        let mut malformed = encoded;
        malformed.push(0);
        std::fs::write(&path, malformed).unwrap();
        assert!(FinalizedCashSnapshot::load_canonical(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
