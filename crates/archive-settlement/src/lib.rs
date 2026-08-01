#![forbid(unsafe_code)]

use activechain_archive::{
    ArchiveCertificate, ArchiveError, RetrievalResponse, Root, TOTAL_SHARDS,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const JOURNAL_MAGIC: &[u8; 8] = b"ACASET01";
pub const MAX_ATTESTATION_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementError {
    Bounds,
    Overflow,
    Identity,
    Sequence,
    Expired,
    Proof,
    Finality,
    Funds,
    Corrupt,
}

impl From<ArchiveError> for SettlementError {
    fn from(_: ArchiveError) -> Self {
        Self::Proof
    }
}

pub trait MissedChallengeVerifier {
    fn verify_missed(&self, attestation: &MissedChallengeAttestation, proof: &[u8]) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissedChallengeAttestation {
    pub chain_genesis: Root,
    pub manifest_root: Root,
    pub provider: Root,
    pub shard_index: u8,
    pub challenge_epoch: u64,
    pub response_deadline_epoch: u64,
    pub finalized_height: u64,
    pub event_sequence: u64,
}

impl MissedChallengeAttestation {
    #[must_use]
    pub fn commitment(self) -> Root {
        digest(&[
            b"ACTIVECHAIN-ARCHIVE-MISSED-CHALLENGE-V1",
            &self.chain_genesis,
            &self.manifest_root,
            &self.provider,
            &[self.shard_index],
            &self.challenge_epoch.to_be_bytes(),
            &self.response_deadline_epoch.to_be_bytes(),
            &self.finalized_height.to_be_bytes(),
            &self.event_sequence.to_be_bytes(),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderSettlement {
    pub provider: Root,
    pub shard_index: u8,
    pub paid_through_epoch: u64,
    pub earned: u128,
    pub collateral_remaining: u128,
    pub slashed: u128,
    pub last_successful_challenge_epoch: u64,
    pub last_missed_challenge_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveSettlement {
    pub chain_genesis: Root,
    pub manifest_root: Root,
    pub opened_epoch: u64,
    pub retention_expiry_epoch: u64,
    pub shard_bytes: u64,
    pub unit_price_per_byte_epoch: u128,
    pub escrow_initial: u128,
    pub escrow_remaining: u128,
    pub collateral_initial: u128,
    pub event_sequence: u64,
    pub providers: [ProviderSettlement; TOTAL_SHARDS],
}

impl ArchiveSettlement {
    pub fn open(
        certificate: &ArchiveCertificate,
        opened_epoch: u64,
        unit_price_per_byte_epoch: u128,
        collateral_per_provider: u128,
        escrow: u128,
    ) -> Result<Self, SettlementError> {
        let manifest = certificate.manifest();
        if opened_epoch == 0
            || opened_epoch >= manifest.retention_expiry_epoch
            || unit_price_per_byte_epoch == 0
            || collateral_per_provider == 0
        {
            return Err(SettlementError::Bounds);
        }
        let epochs = manifest.retention_expiry_epoch - opened_epoch;
        let escrow_initial = reward(manifest.shard_bytes, epochs, unit_price_per_byte_epoch)?
            .checked_mul(TOTAL_SHARDS as u128)
            .ok_or(SettlementError::Overflow)?;
        if escrow != escrow_initial {
            return Err(SettlementError::Funds);
        }
        let collateral_initial = collateral_per_provider
            .checked_mul(TOTAL_SHARDS as u128)
            .ok_or(SettlementError::Overflow)?;
        let providers = std::array::from_fn(|index| ProviderSettlement {
            provider: manifest.assignments[index].provider.principal,
            shard_index: index as u8,
            paid_through_epoch: opened_epoch,
            earned: 0,
            collateral_remaining: collateral_per_provider,
            slashed: 0,
            last_successful_challenge_epoch: 0,
            last_missed_challenge_epoch: 0,
        });
        Ok(Self {
            chain_genesis: manifest.chain_genesis,
            manifest_root: manifest.manifest_root,
            opened_epoch,
            retention_expiry_epoch: manifest.retention_expiry_epoch,
            shard_bytes: manifest.shard_bytes,
            unit_price_per_byte_epoch,
            escrow_initial,
            escrow_remaining: escrow_initial,
            collateral_initial,
            event_sequence: 0,
            providers,
        })
    }

    pub fn settle_custody(
        &mut self,
        certificate: &ArchiveCertificate,
        through_epoch: u64,
        event_sequence: u64,
    ) -> Result<u128, SettlementError> {
        self.check_sequence(event_sequence)?;
        let manifest = certificate.manifest();
        if manifest.chain_genesis != self.chain_genesis
            || manifest.manifest_root != self.manifest_root
            || manifest.shard_bytes != self.shard_bytes
            || manifest.retention_expiry_epoch != self.retention_expiry_epoch
        {
            return Err(SettlementError::Identity);
        }
        if through_epoch <= self.opened_epoch || through_epoch > self.retention_expiry_epoch {
            return Err(SettlementError::Expired);
        }
        let mut total = 0_u128;
        let mut next = self.providers;
        for provider in &mut next {
            if through_epoch <= provider.paid_through_epoch
                || provider.last_successful_challenge_epoch < through_epoch
            {
                return Err(SettlementError::Sequence);
            }
            let epochs = through_epoch - provider.paid_through_epoch;
            let amount = reward(self.shard_bytes, epochs, self.unit_price_per_byte_epoch)?;
            provider.earned =
                provider.earned.checked_add(amount).ok_or(SettlementError::Overflow)?;
            provider.paid_through_epoch = through_epoch;
            total = total.checked_add(amount).ok_or(SettlementError::Overflow)?;
        }
        let remaining = self.escrow_remaining.checked_sub(total).ok_or(SettlementError::Funds)?;
        self.providers = next;
        self.escrow_remaining = remaining;
        self.event_sequence = event_sequence;
        self.validate_conservation()?;
        Ok(total)
    }

    pub fn record_success(
        &mut self,
        certificate: &ArchiveCertificate,
        response: &RetrievalResponse,
        event_sequence: u64,
    ) -> Result<(), SettlementError> {
        self.check_sequence(event_sequence)?;
        let manifest = certificate.manifest();
        if manifest.chain_genesis != self.chain_genesis
            || manifest.manifest_root != self.manifest_root
        {
            return Err(SettlementError::Identity);
        }
        response.verify(manifest)?;
        let challenge = response.challenge;
        if challenge.epoch <= self.opened_epoch || challenge.epoch > self.retention_expiry_epoch {
            return Err(SettlementError::Expired);
        }
        let provider = self.provider_mut(challenge.shard_index, challenge.provider)?;
        if challenge.epoch <= provider.last_successful_challenge_epoch
            || challenge.epoch <= provider.last_missed_challenge_epoch
        {
            return Err(SettlementError::Sequence);
        }
        provider.last_successful_challenge_epoch = challenge.epoch;
        self.event_sequence = event_sequence;
        Ok(())
    }

    pub fn slash_missed<V: MissedChallengeVerifier>(
        &mut self,
        attestation: MissedChallengeAttestation,
        proof: &[u8],
        penalty: u128,
        verifier: &V,
    ) -> Result<u128, SettlementError> {
        self.check_sequence(attestation.event_sequence)?;
        if proof.is_empty() || proof.len() > MAX_ATTESTATION_BYTES || penalty == 0 {
            return Err(SettlementError::Bounds);
        }
        if attestation.chain_genesis != self.chain_genesis
            || attestation.manifest_root != self.manifest_root
        {
            return Err(SettlementError::Identity);
        }
        if attestation.challenge_epoch <= self.opened_epoch
            || attestation.challenge_epoch > self.retention_expiry_epoch
            || attestation.response_deadline_epoch <= attestation.challenge_epoch
            || attestation.finalized_height == 0
        {
            return Err(SettlementError::Expired);
        }
        if !verifier.verify_missed(&attestation, proof) {
            return Err(SettlementError::Finality);
        }
        let provider = self.provider_mut(attestation.shard_index, attestation.provider)?;
        if attestation.challenge_epoch <= provider.last_successful_challenge_epoch
            || attestation.challenge_epoch <= provider.last_missed_challenge_epoch
        {
            return Err(SettlementError::Sequence);
        }
        let slash = penalty.min(provider.collateral_remaining);
        provider.collateral_remaining -= slash;
        provider.slashed = provider.slashed.checked_add(slash).ok_or(SettlementError::Overflow)?;
        provider.last_missed_challenge_epoch = attestation.challenge_epoch;
        self.event_sequence = attestation.event_sequence;
        self.validate_conservation()?;
        Ok(slash)
    }

    pub fn encode_journal(&self) -> Result<Vec<u8>, SettlementError> {
        self.validate_conservation()?;
        let mut bytes = Vec::with_capacity(200 + TOTAL_SHARDS * 121 + 48);
        bytes.extend_from_slice(JOURNAL_MAGIC);
        bytes.extend_from_slice(&self.chain_genesis);
        bytes.extend_from_slice(&self.manifest_root);
        bytes.extend_from_slice(&self.opened_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.retention_expiry_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.shard_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.unit_price_per_byte_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.escrow_initial.to_be_bytes());
        bytes.extend_from_slice(&self.escrow_remaining.to_be_bytes());
        bytes.extend_from_slice(&self.collateral_initial.to_be_bytes());
        bytes.extend_from_slice(&self.event_sequence.to_be_bytes());
        for provider in self.providers {
            bytes.extend_from_slice(&provider.provider);
            bytes.push(provider.shard_index);
            bytes.extend_from_slice(&provider.paid_through_epoch.to_be_bytes());
            bytes.extend_from_slice(&provider.earned.to_be_bytes());
            bytes.extend_from_slice(&provider.collateral_remaining.to_be_bytes());
            bytes.extend_from_slice(&provider.slashed.to_be_bytes());
            bytes.extend_from_slice(&provider.last_successful_challenge_epoch.to_be_bytes());
            bytes.extend_from_slice(&provider.last_missed_challenge_epoch.to_be_bytes());
        }
        let checksum = digest(&[b"ACTIVECHAIN-ARCHIVE-SETTLEMENT-JOURNAL-V1", &bytes]);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    pub fn decode_journal(bytes: &[u8]) -> Result<Self, SettlementError> {
        let expected = 200 + TOTAL_SHARDS * 121 + 48;
        if bytes.len() != expected || &bytes[..8] != JOURNAL_MAGIC {
            return Err(SettlementError::Corrupt);
        }
        let body_end = bytes.len() - 48;
        if digest(&[b"ACTIVECHAIN-ARCHIVE-SETTLEMENT-JOURNAL-V1", &bytes[..body_end]])
            != bytes[body_end..]
        {
            return Err(SettlementError::Corrupt);
        }
        let mut cursor = Cursor::new(&bytes[8..body_end]);
        let chain_genesis = cursor.root()?;
        let manifest_root = cursor.root()?;
        let opened_epoch = cursor.u64()?;
        let retention_expiry_epoch = cursor.u64()?;
        let shard_bytes = cursor.u64()?;
        let unit_price_per_byte_epoch = cursor.u128()?;
        let escrow_initial = cursor.u128()?;
        let escrow_remaining = cursor.u128()?;
        let collateral_initial = cursor.u128()?;
        let event_sequence = cursor.u64()?;
        let mut providers = Vec::with_capacity(TOTAL_SHARDS);
        for _ in 0..TOTAL_SHARDS {
            providers.push(ProviderSettlement {
                provider: cursor.root()?,
                shard_index: cursor.byte()?,
                paid_through_epoch: cursor.u64()?,
                earned: cursor.u128()?,
                collateral_remaining: cursor.u128()?,
                slashed: cursor.u128()?,
                last_successful_challenge_epoch: cursor.u64()?,
                last_missed_challenge_epoch: cursor.u64()?,
            });
        }
        if !cursor.is_empty() {
            return Err(SettlementError::Corrupt);
        }
        let providers = providers.try_into().map_err(|_| SettlementError::Corrupt)?;
        let settlement = Self {
            chain_genesis,
            manifest_root,
            opened_epoch,
            retention_expiry_epoch,
            shard_bytes,
            unit_price_per_byte_epoch,
            escrow_initial,
            escrow_remaining,
            collateral_initial,
            event_sequence,
            providers,
        };
        settlement.validate_shape()?;
        settlement.validate_conservation()?;
        Ok(settlement)
    }

    fn check_sequence(&self, sequence: u64) -> Result<(), SettlementError> {
        if sequence != self.event_sequence.checked_add(1).ok_or(SettlementError::Overflow)? {
            return Err(SettlementError::Sequence);
        }
        Ok(())
    }

    fn provider_mut(
        &mut self,
        shard_index: u8,
        provider: Root,
    ) -> Result<&mut ProviderSettlement, SettlementError> {
        let account =
            self.providers.get_mut(usize::from(shard_index)).ok_or(SettlementError::Bounds)?;
        if account.shard_index != shard_index || account.provider != provider {
            return Err(SettlementError::Identity);
        }
        Ok(account)
    }

    fn validate_shape(&self) -> Result<(), SettlementError> {
        if self.chain_genesis == [0; 48]
            || self.manifest_root == [0; 48]
            || self.opened_epoch == 0
            || self.opened_epoch >= self.retention_expiry_epoch
            || self.shard_bytes == 0
            || self.unit_price_per_byte_epoch == 0
        {
            return Err(SettlementError::Corrupt);
        }
        for (index, provider) in self.providers.iter().enumerate() {
            if provider.provider == [0; 48]
                || usize::from(provider.shard_index) != index
                || provider.paid_through_epoch < self.opened_epoch
                || provider.paid_through_epoch > self.retention_expiry_epoch
            {
                return Err(SettlementError::Corrupt);
            }
        }
        Ok(())
    }

    fn validate_conservation(&self) -> Result<(), SettlementError> {
        let earned = self.providers.iter().try_fold(0_u128, |sum, provider| {
            sum.checked_add(provider.earned).ok_or(SettlementError::Overflow)
        })?;
        if earned.checked_add(self.escrow_remaining) != Some(self.escrow_initial) {
            return Err(SettlementError::Corrupt);
        }
        let collateral = self.providers.iter().try_fold(0_u128, |sum, provider| {
            let account = provider
                .collateral_remaining
                .checked_add(provider.slashed)
                .ok_or(SettlementError::Overflow)?;
            sum.checked_add(account).ok_or(SettlementError::Overflow)
        })?;
        if collateral != self.collateral_initial {
            return Err(SettlementError::Corrupt);
        }
        Ok(())
    }
}

fn reward(shard_bytes: u64, epochs: u64, unit_price: u128) -> Result<u128, SettlementError> {
    if shard_bytes == 0 || epochs == 0 || unit_price == 0 {
        return if epochs == 0 { Ok(0) } else { Err(SettlementError::Bounds) };
    }
    u128::from(shard_bytes)
        .checked_mul(u128::from(epochs))
        .and_then(|value| value.checked_mul(unit_price))
        .ok_or(SettlementError::Overflow)
}

fn digest(parts: &[&[u8]]) -> Root {
    let mut hasher = Shake256::default();
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    let mut output = [0; 48];
    reader.read(&mut output);
    output
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SettlementError> {
        let end = self.offset.checked_add(length).ok_or(SettlementError::Overflow)?;
        let value = self.bytes.get(self.offset..end).ok_or(SettlementError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, SettlementError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, SettlementError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| SettlementError::Corrupt)?))
    }

    fn u128(&mut self) -> Result<u128, SettlementError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().map_err(|_| SettlementError::Corrupt)?))
    }

    fn root(&mut self) -> Result<Root, SettlementError> {
        self.take(48)?.try_into().map_err(|_| SettlementError::Corrupt)
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[must_use]
pub fn render_settlement_fixture() -> String {
    let per_provider = reward(2_048, 30, 3).expect("fixture reward");
    format!(
        "fixture_version=1\nshard_bytes=2048\nepochs=30\nunit_price=3\nper_provider_reward={per_provider}\ntotal_escrow={}\n",
        per_provider * TOTAL_SHARDS as u128
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_archive::{
        ArchiveBundle, ArchiveDataClass, ArchiveProvider, CustodyReceipt, ReceiptVerifier,
        RetrievalChallenge,
    };

    struct TestVerifier;

    impl ReceiptVerifier for TestVerifier {
        fn verify(&self, provider: Root, statement: Root, signature: &[u8]) -> bool {
            signature == [provider.as_slice(), statement.as_slice()].concat()
        }
    }

    impl MissedChallengeVerifier for TestVerifier {
        fn verify_missed(&self, attestation: &MissedChallengeAttestation, proof: &[u8]) -> bool {
            proof == attestation.commitment()
        }
    }

    fn root(value: u8) -> Root {
        [value; 48]
    }

    fn fixture() -> (ArchiveBundle, ArchiveCertificate) {
        let providers = std::array::from_fn(|index| {
            ArchiveProvider::new(root((index + 10) as u8), root((index / 3 + 100) as u8)).unwrap()
        });
        let bundle = ArchiveBundle::encode(
            b"archive settlement payload",
            root(1),
            ArchiveDataClass::Ledger,
            1,
            5,
            100,
            providers,
        )
        .unwrap();
        let receipts = bundle
            .manifest
            .assignments
            .iter()
            .map(|assignment| {
                let mut receipt = CustodyReceipt {
                    provider: assignment.provider.principal,
                    shard_index: assignment.shard_index,
                    manifest_root: bundle.manifest.manifest_root,
                    retention_expiry_epoch: bundle.manifest.retention_expiry_epoch,
                    signature: Vec::new(),
                };
                receipt.signature =
                    [receipt.provider.as_slice(), receipt.statement().as_slice()].concat();
                receipt
            })
            .collect();
        let certificate =
            ArchiveCertificate::new(bundle.manifest.clone(), receipts, 10, &TestVerifier).unwrap();
        (bundle, certificate)
    }

    fn settlement(certificate: &ArchiveCertificate) -> ArchiveSettlement {
        let manifest = certificate.manifest();
        let escrow = reward(manifest.shard_bytes, 90, 3).unwrap() * TOTAL_SHARDS as u128;
        ArchiveSettlement::open(certificate, 10, 3, 1_000, escrow).unwrap()
    }

    fn record_all_successes(
        state: &mut ArchiveSettlement,
        bundle: &ArchiveBundle,
        certificate: &ArchiveCertificate,
        epoch: u64,
        first_sequence: u64,
    ) {
        for index in 0..TOTAL_SHARDS {
            let challenge = RetrievalChallenge::derive(
                &bundle.manifest,
                index as u8,
                epoch,
                root((index + 50) as u8),
            )
            .unwrap();
            let response = bundle.shards[index].answer(challenge, &bundle.manifest).unwrap();
            state.record_success(certificate, &response, first_sequence + index as u64).unwrap();
        }
    }

    #[test]
    fn custody_rewards_are_exact_once_and_conserve_escrow() {
        let (bundle, certificate) = fixture();
        let mut state = settlement(&certificate);
        record_all_successes(&mut state, &bundle, &certificate, 40, 1);
        let first = state.settle_custody(&certificate, 40, 13).unwrap();
        assert_eq!(first, reward(state.shard_bytes, 30, 3).unwrap() * 12);
        assert_eq!(state.settle_custody(&certificate, 40, 14), Err(SettlementError::Sequence));
        record_all_successes(&mut state, &bundle, &certificate, 100, 14);
        state.settle_custody(&certificate, 100, 26).unwrap();
        assert_eq!(state.escrow_remaining, 0);
        assert_eq!(state.settle_custody(&certificate, 100, 27), Err(SettlementError::Sequence));
    }

    #[test]
    fn successful_response_blocks_same_epoch_slash_and_missed_attestation_is_bounded() {
        let (bundle, certificate) = fixture();
        let mut state = settlement(&certificate);
        let challenge = RetrievalChallenge::derive(&bundle.manifest, 3, 20, root(44)).unwrap();
        let response = bundle.shards[3].answer(challenge, &bundle.manifest).unwrap();
        state.record_success(&certificate, &response, 1).unwrap();
        let mut missed = MissedChallengeAttestation {
            chain_genesis: bundle.manifest.chain_genesis,
            manifest_root: bundle.manifest.manifest_root,
            provider: challenge.provider,
            shard_index: 3,
            challenge_epoch: 20,
            response_deadline_epoch: 21,
            finalized_height: 50,
            event_sequence: 2,
        };
        assert_eq!(
            state.slash_missed(missed, &missed.commitment(), 500, &TestVerifier),
            Err(SettlementError::Sequence)
        );
        missed.shard_index = 4;
        missed.provider = bundle.manifest.assignments[4].provider.principal;
        assert_eq!(
            state.slash_missed(missed, &missed.commitment(), 2_000, &TestVerifier),
            Ok(1_000)
        );
        assert_eq!(state.providers[4].collateral_remaining, 0);
        assert_eq!(
            state.slash_missed(missed, &missed.commitment(), 1, &TestVerifier),
            Err(SettlementError::Sequence)
        );
    }

    #[test]
    fn journal_round_trip_and_substitution_fail_closed() {
        let (bundle, certificate) = fixture();
        let mut state = settlement(&certificate);
        record_all_successes(&mut state, &bundle, &certificate, 40, 1);
        state.settle_custody(&certificate, 40, 13).unwrap();
        let bytes = state.encode_journal().unwrap();
        assert_eq!(ArchiveSettlement::decode_journal(&bytes).unwrap(), state);
        let mut corrupt = bytes;
        corrupt[80] ^= 1;
        assert_eq!(ArchiveSettlement::decode_journal(&corrupt), Err(SettlementError::Corrupt));
    }

    #[test]
    fn checked_in_settlement_fixture_does_not_drift() {
        assert_eq!(
            render_settlement_fixture(),
            include_str!("../../../testing/storage/archive-settlement-v1.txt")
        );
    }
}
