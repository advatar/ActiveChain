#![forbid(unsafe_code)]

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_finality_types::{FinalityCertificateBundle, FinalizedBlockHeader};
use activechain_protocol_types::{
    ChainId, ConsensusUpgradeAuthorization, Digest384, MAX_VALIDATORS_PER_EPOCH, QuorumCertificate,
    ValidatorGenesis, ValidatorVote,
};
use activechain_rpc_server::{RpcProofError, verify_query_record_with_chain_genesis};
use activechain_rpc_types::QueryRecord;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

pub const LIGHT_CLIENT_SCHEMA_REVISION: u32 = 1;
pub const MAX_WEAK_SUBJECTIVITY_WINDOW: u64 = 1_000_000;
pub const MAX_RETIRED_VALIDATOR_SETS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LightClientError {
    Malformed,
    WrongChain,
    WrongGenesis,
    WrongValidatorSet,
    WrongRevision,
    InvalidFinality,
    Stale,
    Fork,
    Height,
    Overflow,
    Proof,
    Persistence,
    Corrupt,
    Upgrade,
    RetiredValidatorSet,
    DataAvailability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeCertificateBundle {
    authorization: ConsensusUpgradeAuthorization,
    certificate: QuorumCertificate,
    votes: Vec<ValidatorVote>,
    next_genesis: ValidatorGenesis,
}
impl UpgradeCertificateBundle {
    pub const TYPE_TAG: u16 = 0x00a5;
    pub const SCHEMA_VERSION: u16 = 1;
    pub const MAX_ENCODED_LEN: usize = ConsensusUpgradeAuthorization::ENCODED_LENGTH
        + QuorumCertificate::ENCODED_LENGTH
        + 1
        + MAX_VALIDATORS_PER_EPOCH * ValidatorVote::MAX_ENCODED_LEN
        + ValidatorGenesis::MAX_ENCODED_LEN;
    pub fn new(
        authorization: ConsensusUpgradeAuthorization,
        certificate: QuorumCertificate,
        votes: Vec<ValidatorVote>,
        next_genesis: ValidatorGenesis,
    ) -> Result<Self, LightClientError> {
        if votes.is_empty() || votes.len() > MAX_VALIDATORS_PER_EPOCH {
            return Err(LightClientError::Malformed);
        }
        Ok(Self { authorization, certificate, votes, next_genesis })
    }
    pub const fn authorization(&self) -> ConsensusUpgradeAuthorization {
        self.authorization
    }
    pub const fn certificate(&self) -> &QuorumCertificate {
        &self.certificate
    }
    pub fn votes(&self) -> &[ValidatorVote] {
        &self.votes
    }
    pub const fn next_genesis(&self) -> &ValidatorGenesis {
        &self.next_genesis
    }
}
impl CanonicalEncode for UpgradeCertificateBundle {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.authorization.encode(encoder)?;
        self.certificate.encode(encoder)?;
        encoder.write_length(self.votes.len(), MAX_VALIDATORS_PER_EPOCH)?;
        for vote in &self.votes {
            vote.encode(encoder)?;
        }
        self.next_genesis.encode(encoder)
    }
}
impl CanonicalDecode for UpgradeCertificateBundle {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let authorization = ConsensusUpgradeAuthorization::decode(decoder)?;
        let certificate = QuorumCertificate::decode(decoder)?;
        let count = decoder.read_length(MAX_VALIDATORS_PER_EPOCH)?;
        let mut votes = Vec::with_capacity(count);
        for _ in 0..count {
            votes.push(ValidatorVote::decode(decoder)?);
        }
        let next_genesis = ValidatorGenesis::decode(decoder)?;
        Self::new(authorization, certificate, votes, next_genesis)
            .map_err(|_| DecodeError::InvalidValue("invalid upgrade certificate bundle"))
    }
}
impl CanonicalType for UpgradeCertificateBundle {
    const TYPE_TAG: u16 = Self::TYPE_TAG;
    const SCHEMA_VERSION: u16 = Self::SCHEMA_VERSION;
    const MAX_ENCODED_LEN: usize = Self::MAX_ENCODED_LEN;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LightClientState {
    chain_id: ChainId,
    chain_genesis_commitment: Digest384,
    active_genesis: ValidatorGenesis,
    finalized_header: FinalizedBlockHeader,
    weak_subjectivity_period: u64,
    weak_subjectivity_until: u64,
    retired_validator_set_roots: Vec<Digest384>,
    pending_upgrade: Option<UpgradeCertificateBundle>,
}

impl LightClientState {
    pub fn bootstrap(
        expected_chain: ChainId,
        chain_genesis_commitment: Digest384,
        checkpoint: &FinalityCertificateBundle,
        weak_subjectivity_period: u64,
    ) -> Result<Self, LightClientError> {
        if chain_genesis_commitment == Digest384::ZERO
            || weak_subjectivity_period == 0
            || weak_subjectivity_period > MAX_WEAK_SUBJECTIVITY_WINDOW
        {
            return Err(LightClientError::Malformed);
        }
        verify_finality(checkpoint, chain_genesis_commitment)?;
        let header = checkpoint.header();
        if header.inputs.chain_id != expected_chain {
            return Err(LightClientError::WrongChain);
        }
        let until = header
            .inputs
            .height
            .checked_add(weak_subjectivity_period)
            .ok_or(LightClientError::Overflow)?;
        Ok(Self {
            chain_id: expected_chain,
            chain_genesis_commitment,
            active_genesis: checkpoint.validator_genesis().clone(),
            finalized_header: header,
            weak_subjectivity_period,
            weak_subjectivity_until: until,
            retired_validator_set_roots: Vec::new(),
            pending_upgrade: None,
        })
    }

    pub fn ingest_finality(
        &mut self,
        bundle: &FinalityCertificateBundle,
        observed_network_height: u64,
    ) -> Result<(), LightClientError> {
        if observed_network_height > self.weak_subjectivity_until {
            return Err(LightClientError::Stale);
        }
        let mut activating = false;
        let expected_genesis = if let Some(upgrade) = &self.pending_upgrade {
            let activation = upgrade.authorization.activation_height();
            if header_height(bundle) > activation {
                return Err(LightClientError::Upgrade);
            }
            if header_height(bundle) == activation {
                activating = true;
                upgrade.next_genesis()
            } else {
                &self.active_genesis
            }
        } else {
            &self.active_genesis
        };
        verify_finality(bundle, self.chain_genesis_commitment)?;
        let header = bundle.header();
        if header.inputs.chain_id != self.chain_id {
            return Err(LightClientError::WrongChain);
        }
        if bundle.validator_genesis() != expected_genesis {
            return Err(LightClientError::WrongValidatorSet);
        }
        if header.inputs.epoch != expected_genesis.epoch()
            || header.inputs.protocol_revision != expected_genesis.protocol_revision()
        {
            return Err(LightClientError::WrongRevision);
        }
        let expected_height =
            self.finalized_header.inputs.height.checked_add(1).ok_or(LightClientError::Overflow)?;
        if header.inputs.height != expected_height || header.inputs.height > observed_network_height
        {
            return Err(LightClientError::Height);
        }
        let parent = self.finalized_header.digest().map_err(|_| LightClientError::Malformed)?;
        if header.inputs.parent_block_id != parent {
            return Err(LightClientError::Fork);
        }
        self.weak_subjectivity_until = header
            .inputs
            .height
            .checked_add(self.weak_subjectivity_period)
            .ok_or(LightClientError::Overflow)?;
        self.finalized_header = header;
        if activating {
            let upgrade = self.pending_upgrade.take().ok_or(LightClientError::Upgrade)?;
            if upgrade.authorization.changes_validator_set() {
                if self.retired_validator_set_roots.len() == MAX_RETIRED_VALIDATOR_SETS {
                    self.retired_validator_set_roots.remove(0);
                }
                self.retired_validator_set_roots.push(self.active_genesis.validator_set_root());
            }
            self.active_genesis = upgrade.next_genesis;
        }
        Ok(())
    }

    pub fn authorize_upgrade(
        &mut self,
        bundle: UpgradeCertificateBundle,
    ) -> Result<(), LightClientError> {
        if self.pending_upgrade.is_some() {
            return Err(LightClientError::Upgrade);
        }
        let authorization = bundle.authorization;
        if authorization.authorization_height() > self.finalized_header.inputs.height
            || authorization.activation_height() <= self.finalized_header.inputs.height
            || authorization.from_epoch() != self.active_genesis.epoch()
            || authorization.previous_validator_set_root()
                != self.active_genesis.validator_set_root()
            || authorization.previous_protocol_revision() != self.active_genesis.protocol_revision()
            || authorization.to_epoch() != bundle.next_genesis.epoch()
            || authorization.activation_height() != bundle.next_genesis.activation_height()
            || authorization.next_validator_set_root() != bundle.next_genesis.validator_set_root()
            || authorization.next_protocol_revision() != bundle.next_genesis.protocol_revision()
        {
            return Err(LightClientError::Upgrade);
        }
        if self.retired_validator_set_roots.contains(&authorization.next_validator_set_root()) {
            return Err(LightClientError::RetiredValidatorSet);
        }
        let certificate = &bundle.certificate;
        if certificate.genesis_commitment() != self.chain_genesis_commitment
            || certificate.epoch() != self.active_genesis.epoch()
            || certificate.validator_set_root() != self.active_genesis.validator_set_root()
            || certificate.protocol_revision() != self.active_genesis.protocol_revision()
            || certificate.height() != authorization.authorization_height()
            || certificate.block_digest() != authorization.commitment()
        {
            return Err(LightClientError::Upgrade);
        }
        let validator_set =
            self.active_genesis.validator_set().map_err(|_| LightClientError::Upgrade)?;
        let mut votes = Vec::with_capacity(bundle.votes.len());
        for vote in &bundle.votes {
            let entry = self
                .active_genesis
                .entries()
                .iter()
                .find(|entry| entry.validator() == vote.validator())
                .ok_or(LightClientError::Upgrade)?;
            votes.push((entry.public_key().as_slice(), vote.clone()));
        }
        activechain_consensus_verifier::verify_quorum_certificate(
            certificate,
            &validator_set,
            &votes,
        )
        .map_err(|_| LightClientError::Upgrade)?;
        self.pending_upgrade = Some(bundle);
        Ok(())
    }

    pub fn verify_data_availability(&self, serialized: &[u8]) -> Result<(), LightClientError> {
        let batch = activechain_data_availability::AvailabilityBatch::deserialize(serialized)
            .map_err(|_| LightClientError::DataAvailability)?;
        let commitment =
            batch.payload_commitment().map_err(|_| LightClientError::DataAvailability)?;
        if commitment.as_bytes()
            != self.finalized_header.inputs.data_availability_commitment.as_bytes()
        {
            return Err(LightClientError::DataAvailability);
        }
        Ok(())
    }

    pub fn verify_query(&self, record: &QueryRecord) -> Result<(), LightClientError> {
        if record.finalized_height() != self.finalized_header.inputs.height {
            return Err(LightClientError::Height);
        }
        let bundle = decode_envelope::<FinalityCertificateBundle>(record.finality())
            .map_err(|_| LightClientError::Proof)?;
        if bundle.header() != self.finalized_header {
            return Err(LightClientError::Fork);
        }
        verify_query_record_with_chain_genesis(record, self.chain_genesis_commitment)
            .map_err(|_: RpcProofError| LightClientError::Proof)
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn chain_genesis_commitment(&self) -> Digest384 {
        self.chain_genesis_commitment
    }
    pub const fn finalized_header(&self) -> FinalizedBlockHeader {
        self.finalized_header
    }
    pub const fn active_validator_genesis(&self) -> &ValidatorGenesis {
        &self.active_genesis
    }
    pub fn pending_upgrade(&self) -> Option<&UpgradeCertificateBundle> {
        self.pending_upgrade.as_ref()
    }
    pub const fn weak_subjectivity_until(&self) -> u64 {
        self.weak_subjectivity_until
    }
}

fn header_height(bundle: &FinalityCertificateBundle) -> u64 {
    bundle.header().inputs.height
}

fn verify_finality(
    bundle: &FinalityCertificateBundle,
    chain_genesis_commitment: Digest384,
) -> Result<(), LightClientError> {
    let header = bundle.header();
    let genesis = bundle.validator_genesis();
    let certificate = bundle.certificate();
    if certificate.genesis_commitment() != chain_genesis_commitment {
        return Err(LightClientError::WrongGenesis);
    }
    if genesis.epoch() != header.inputs.epoch
        || genesis.protocol_revision() != header.inputs.protocol_revision
        || genesis.validator_set_root() != header.inputs.validator_set_root
        || certificate.epoch() != header.inputs.epoch
        || certificate.protocol_revision() != header.inputs.protocol_revision
        || certificate.validator_set_root() != header.inputs.validator_set_root
        || certificate.height() != header.inputs.height
        || header.digest().map_err(|_| LightClientError::Malformed)? != certificate.block_digest()
    {
        return Err(LightClientError::InvalidFinality);
    }
    let validator_set = genesis.validator_set().map_err(|_| LightClientError::InvalidFinality)?;
    let mut votes: Vec<(&[u8], ValidatorVote)> = Vec::with_capacity(bundle.votes().len());
    for vote in bundle.votes() {
        let entry = genesis
            .entries()
            .iter()
            .find(|entry| entry.validator() == vote.validator())
            .ok_or(LightClientError::InvalidFinality)?;
        votes.push((entry.public_key().as_slice(), vote.clone()));
    }
    activechain_consensus_verifier::verify_quorum_certificate(certificate, &validator_set, &votes)
        .map_err(|_| LightClientError::InvalidFinality)
}

impl CanonicalEncode for LightClientState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        LIGHT_CLIENT_SCHEMA_REVISION.encode(encoder)?;
        self.chain_id.encode(encoder)?;
        self.chain_genesis_commitment.encode(encoder)?;
        self.active_genesis.encode(encoder)?;
        self.finalized_header.encode(encoder)?;
        self.weak_subjectivity_period.encode(encoder)?;
        self.weak_subjectivity_until.encode(encoder)?;
        encoder.write_length(self.retired_validator_set_roots.len(), MAX_RETIRED_VALIDATOR_SETS)?;
        for root in &self.retired_validator_set_roots {
            root.encode(encoder)?;
        }
        self.pending_upgrade.encode(encoder)
    }
}
impl CanonicalDecode for LightClientState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if u32::decode(decoder)? != LIGHT_CLIENT_SCHEMA_REVISION {
            return Err(DecodeError::InvalidValue("unsupported light-client schema"));
        }
        let chain_id = ChainId::decode(decoder)?;
        let chain_genesis_commitment = Digest384::decode(decoder)?;
        let active_genesis = ValidatorGenesis::decode(decoder)?;
        let finalized_header = FinalizedBlockHeader::decode(decoder)?;
        let weak_subjectivity_period = u64::decode(decoder)?;
        let weak_subjectivity_until = u64::decode(decoder)?;
        let retired_count = decoder.read_length(MAX_RETIRED_VALIDATOR_SETS)?;
        let mut retired_validator_set_roots = Vec::with_capacity(retired_count);
        for _ in 0..retired_count {
            let root = Digest384::decode(decoder)?;
            if root == Digest384::ZERO || retired_validator_set_roots.contains(&root) {
                return Err(DecodeError::InvalidValue("invalid retired validator-set history"));
            }
            retired_validator_set_roots.push(root);
        }
        let pending_upgrade = Option::<UpgradeCertificateBundle>::decode(decoder)?;
        let mut value = Self {
            chain_id,
            chain_genesis_commitment,
            active_genesis,
            finalized_header,
            weak_subjectivity_period,
            weak_subjectivity_until,
            retired_validator_set_roots,
            pending_upgrade: None,
        };
        let minimum_until = value
            .finalized_header
            .inputs
            .height
            .checked_add(value.weak_subjectivity_period)
            .ok_or(DecodeError::InvalidValue("light-client subjectivity height overflow"))?;
        if value.chain_genesis_commitment == Digest384::ZERO
            || value.weak_subjectivity_period == 0
            || value.weak_subjectivity_period > MAX_WEAK_SUBJECTIVITY_WINDOW
            || value.finalized_header.inputs.chain_id != value.chain_id
            || value.finalized_header.inputs.epoch != value.active_genesis.epoch()
            || value.finalized_header.inputs.protocol_revision
                != value.active_genesis.protocol_revision()
            || value.finalized_header.inputs.validator_set_root
                != value.active_genesis.validator_set_root()
            || value
                .retired_validator_set_roots
                .contains(&value.active_genesis.validator_set_root())
            || value.weak_subjectivity_until < minimum_until
        {
            return Err(DecodeError::InvalidValue("invalid light-client state"));
        }
        if let Some(upgrade) = pending_upgrade {
            value
                .authorize_upgrade(upgrade)
                .map_err(|_| DecodeError::InvalidValue("invalid pending light-client upgrade"))?;
        }
        Ok(value)
    }
}
impl CanonicalType for LightClientState {
    const TYPE_TAG: u16 = 0x00a4;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 4
        + 48
        + 48
        + ValidatorGenesis::MAX_ENCODED_LEN
        + FinalizedBlockHeader::MAX_ENCODED_LEN
        + 16
        + 1
        + MAX_RETIRED_VALIDATOR_SETS * 48
        + 1
        + UpgradeCertificateBundle::MAX_ENCODED_LEN;
}

pub struct PersistentLightClient {
    path: PathBuf,
    state: LightClientState,
}
impl PersistentLightClient {
    pub fn create(path: PathBuf, state: LightClientState) -> Result<Self, LightClientError> {
        save_state(&path, &state)?;
        Ok(Self { path, state })
    }
    pub fn load(path: PathBuf) -> Result<Self, LightClientError> {
        let state = load_state(&path)?;
        Ok(Self { path, state })
    }
    pub const fn state(&self) -> &LightClientState {
        &self.state
    }
    pub fn ingest_finality(
        &mut self,
        bundle: &FinalityCertificateBundle,
        observed_network_height: u64,
    ) -> Result<(), LightClientError> {
        let mut next = self.state.clone();
        next.ingest_finality(bundle, observed_network_height)?;
        save_state(&self.path, &next)?;
        self.state = next;
        Ok(())
    }
    pub fn authorize_upgrade(
        &mut self,
        bundle: UpgradeCertificateBundle,
    ) -> Result<(), LightClientError> {
        let mut next = self.state.clone();
        next.authorize_upgrade(bundle)?;
        save_state(&self.path, &next)?;
        self.state = next;
        Ok(())
    }
}

fn save_state(path: &Path, state: &LightClientState) -> Result<(), LightClientError> {
    let bytes = encode_envelope(state).map_err(|_| LightClientError::Persistence)?;
    let tag = snapshot_tag(&bytes);
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary).map_err(|_| LightClientError::Persistence)?;
    file.write_all(&bytes).map_err(|_| LightClientError::Persistence)?;
    file.write_all(&tag).map_err(|_| LightClientError::Persistence)?;
    file.sync_all().map_err(|_| LightClientError::Persistence)?;
    std::fs::rename(&temporary, path).map_err(|_| LightClientError::Persistence)?;
    let parent =
        path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| LightClientError::Persistence)
}
fn load_state(path: &Path) -> Result<LightClientState, LightClientError> {
    let bytes = std::fs::read(path).map_err(|_| LightClientError::Persistence)?;
    if bytes.len() < 32 {
        return Err(LightClientError::Corrupt);
    }
    let body = bytes.len() - 32;
    if snapshot_tag(&bytes[..body]) != bytes[body..] {
        return Err(LightClientError::Corrupt);
    }
    decode_envelope(&bytes[..body]).map_err(|_| LightClientError::Corrupt)
}
fn snapshot_tag(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-LIGHT-CLIENT-SNAPSHOT-V1");
    hasher.update(bytes);
    let mut output = [0; 32];
    hasher.finalize_xof().read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{
        ConsensusVoteContext, CryptoSuiteId, PrincipalId, ProtocolSignature, QuorumCertificate,
        ValidatorGenesisEntry,
    };
    use activechain_state_tree::StateCommitment;
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn bundle(
        key: &SigningKey<MlDsa44>,
        genesis: &ValidatorGenesis,
        chain_genesis: Digest384,
        height: u64,
        parent: Digest384,
    ) -> FinalityCertificateBundle {
        let header = FinalizedBlockHeader {
            inputs: activechain_finality_types::ProofPublicInputs {
                chain_id: ChainId::new(digest(1)),
                epoch: genesis.epoch(),
                height,
                protocol_revision: genesis.protocol_revision(),
                validator_set_root: genesis.validator_set_root(),
                parent_block_id: parent,
                pre_state: StateCommitment::new(digest(10), 0),
                authorization_root: digest(11),
                action_root: digest(12),
                execution_order_root: digest(13),
                total_fees: 0,
                pre_supply: 0,
                issuance: 0,
                burn: 0,
                post_supply: 0,
                post_state: StateCommitment::new(digest(14), 0),
                receipt_root: digest(15),
                data_availability_commitment: digest(16),
            },
            proof_statement_commitment: digest(17),
        };
        let context = ConsensusVoteContext::new_with_revision(
            chain_genesis,
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let unsigned = ValidatorVote::new(
            genesis.entries()[0].validator(),
            context,
            height,
            2,
            header.digest().unwrap(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        let vote = ValidatorVote::new(
            genesis.entries()[0].validator(),
            context,
            height,
            2,
            header.digest().unwrap(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap();
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        hasher.update(key.verifying_key().encode().as_slice());
        hasher.update(&vote.signing_payload());
        hasher.update(vote.signature().as_bytes());
        let mut root = [0; 48];
        hasher.finalize_xof().read(&mut root);
        let certificate = QuorumCertificate::new(
            context,
            height,
            2,
            header.digest().unwrap(),
            Digest384::new(root),
            1,
            1,
        )
        .unwrap();
        FinalityCertificateBundle::new(header, genesis.clone(), certificate, vec![vote]).unwrap()
    }
    fn fixture() -> (SigningKey<MlDsa44>, ValidatorGenesis, Digest384, FinalityCertificateBundle) {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([1; 32]));
        let genesis = ValidatorGenesis::new_with_revision(
            1,
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    PrincipalId::new(digest(2)),
                    1,
                    key.verifying_key().encode().into(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let chain_genesis = genesis.genesis_commitment();
        let first = bundle(&key, &genesis, chain_genesis, 1, digest(3));
        (key, genesis, chain_genesis, first)
    }
    fn upgrade_bundle(
        key: &SigningKey<MlDsa44>,
        current: &ValidatorGenesis,
        chain_genesis: Digest384,
        authorization: ConsensusUpgradeAuthorization,
        next: ValidatorGenesis,
    ) -> UpgradeCertificateBundle {
        let context = ConsensusVoteContext::new_with_revision(
            chain_genesis,
            current.epoch(),
            current.validator_set_root(),
            current.protocol_revision(),
        )
        .unwrap();
        let unsigned = ValidatorVote::new(
            current.entries()[0].validator(),
            context,
            authorization.authorization_height(),
            2,
            authorization.commitment(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        let vote = ValidatorVote::new(
            current.entries()[0].validator(),
            context,
            authorization.authorization_height(),
            2,
            authorization.commitment(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap();
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        hasher.update(key.verifying_key().encode().as_slice());
        hasher.update(&vote.signing_payload());
        hasher.update(vote.signature().as_bytes());
        let mut root = [0; 48];
        hasher.finalize_xof().read(&mut root);
        let certificate = QuorumCertificate::new(
            context,
            authorization.authorization_height(),
            2,
            authorization.commitment(),
            Digest384::new(root),
            1,
            1,
        )
        .unwrap();
        UpgradeCertificateBundle::new(authorization, certificate, vec![vote], next).unwrap()
    }
    fn temporary(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "activechain-light-{name}-{}-{}.snapshot",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn bootstrap_update_fork_stale_restart_and_corruption_fail_closed() {
        let (key, genesis, chain_genesis, first) = fixture();
        let state = LightClientState::bootstrap(ChainId::new(digest(1)), chain_genesis, &first, 10)
            .unwrap();
        let path = temporary("lifecycle");
        let _ = std::fs::remove_file(&path);
        let mut client = PersistentLightClient::create(path.clone(), state).unwrap();
        let second = bundle(&key, &genesis, chain_genesis, 2, first.header().digest().unwrap());
        client.ingest_finality(&second, 2).unwrap();
        assert_eq!(client.state().finalized_header().inputs.height, 2);
        drop(client);
        let mut client = PersistentLightClient::load(path.clone()).unwrap();
        assert_eq!(client.state().finalized_header().inputs.height, 2);

        let fork = bundle(&key, &genesis, chain_genesis, 3, digest(99));
        assert_eq!(client.ingest_finality(&fork, 3), Err(LightClientError::Fork));
        let third = bundle(&key, &genesis, chain_genesis, 3, second.header().digest().unwrap());
        assert_eq!(client.ingest_finality(&third, 13), Err(LightClientError::Stale));

        let mut corrupt = std::fs::read(&path).unwrap();
        corrupt[8] ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        assert!(matches!(
            PersistentLightClient::load(path.clone()),
            Err(LightClientError::Corrupt)
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bootstrap_rejects_wrong_chain_genesis_and_bad_signature() {
        let (_, _, chain_genesis, first) = fixture();
        assert_eq!(
            LightClientState::bootstrap(ChainId::new(digest(9)), chain_genesis, &first, 10),
            Err(LightClientError::WrongChain)
        );
        assert_eq!(
            LightClientState::bootstrap(ChainId::new(digest(1)), digest(9), &first, 10),
            Err(LightClientError::WrongGenesis)
        );
        let mut malformed = encode_envelope(&first).unwrap();
        let last = malformed.len() - 1;
        malformed[last] ^= 1;
        let malformed = decode_envelope::<FinalityCertificateBundle>(&malformed).unwrap();
        assert_eq!(
            LightClientState::bootstrap(ChainId::new(digest(1)), chain_genesis, &malformed, 10),
            Err(LightClientError::InvalidFinality)
        );
    }

    #[test]
    fn finalized_upgrade_changes_active_set_and_rejects_retired_reactivation() {
        let (current_key, current, chain_genesis, first) = fixture();
        let mut state =
            LightClientState::bootstrap(ChainId::new(digest(1)), chain_genesis, &first, 10)
                .unwrap();
        let next_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([2; 32]));
        let next = ValidatorGenesis::new_with_revision(
            2,
            2,
            2,
            vec![
                ValidatorGenesisEntry::new(
                    PrincipalId::new(digest(20)),
                    1,
                    next_key.verifying_key().encode().into(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let authorization = ConsensusUpgradeAuthorization::new(
            1,
            2,
            current.epoch(),
            next.epoch(),
            current.validator_set_root(),
            next.validator_set_root(),
            current.protocol_revision(),
            next.protocol_revision(),
        )
        .unwrap();
        state
            .authorize_upgrade(upgrade_bundle(
                &current_key,
                &current,
                chain_genesis,
                authorization,
                next.clone(),
            ))
            .unwrap();
        let restored =
            decode_envelope::<LightClientState>(&encode_envelope(&state).unwrap()).unwrap();
        assert_eq!(restored.pending_upgrade(), state.pending_upgrade());

        let wrong_revision = ValidatorGenesis::new_with_revision(
            2,
            3,
            2,
            vec![
                ValidatorGenesisEntry::new(
                    PrincipalId::new(digest(20)),
                    1,
                    next_key.verifying_key().encode().into(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let wrong_revision_authorization = ConsensusUpgradeAuthorization::new(
            1,
            2,
            current.epoch(),
            wrong_revision.epoch(),
            current.validator_set_root(),
            wrong_revision.validator_set_root(),
            current.protocol_revision(),
            2,
        )
        .unwrap();
        let mut rejecting_state =
            LightClientState::bootstrap(ChainId::new(digest(1)), chain_genesis, &first, 10)
                .unwrap();
        assert_eq!(
            rejecting_state.authorize_upgrade(upgrade_bundle(
                &current_key,
                &current,
                chain_genesis,
                wrong_revision_authorization,
                wrong_revision,
            )),
            Err(LightClientError::Upgrade)
        );

        let second = bundle(&next_key, &next, chain_genesis, 2, first.header().digest().unwrap());
        state.ingest_finality(&second, 2).unwrap();
        assert_eq!(state.finalized_header().inputs.epoch, 2);
        assert_eq!(state.finalized_header().inputs.protocol_revision, 2);

        let retired =
            ValidatorGenesis::new_with_revision(3, 3, 2, current.entries().to_vec()).unwrap();
        let reactivate = ConsensusUpgradeAuthorization::new(
            2,
            3,
            next.epoch(),
            retired.epoch(),
            next.validator_set_root(),
            retired.validator_set_root(),
            next.protocol_revision(),
            retired.protocol_revision(),
        )
        .unwrap();
        assert_eq!(
            state.authorize_upgrade(upgrade_bundle(
                &next_key,
                &next,
                chain_genesis,
                reactivate,
                retired,
            )),
            Err(LightClientError::RetiredValidatorSet)
        );
    }

    #[test]
    fn data_availability_reconstruction_is_bound_to_finalized_commitment() {
        let (_, _, chain_genesis, first) = fixture();
        let mut state =
            LightClientState::bootstrap(ChainId::new(digest(1)), chain_genesis, &first, 10)
                .unwrap();
        let batch =
            activechain_data_availability::AvailabilityBatch::encode(b"finalized payload", 2, 1)
                .unwrap();
        state.finalized_header.inputs.data_availability_commitment =
            Digest384::new(*batch.payload_commitment().unwrap().as_bytes());
        let encoded = batch.serialize().unwrap();
        assert_eq!(state.verify_data_availability(&encoded), Ok(()));
        let mut substituted = encoded;
        let last = substituted.len() - 1;
        substituted[last] ^= 1;
        assert_eq!(
            state.verify_data_availability(&substituted),
            Err(LightClientError::DataAvailability)
        );
    }
}
