#![forbid(unsafe_code)]

//! Deterministic in-memory consensus boundary for the first PQ testnet runtime.

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_crypto_provider::{
    VerificationError, verify_block_proposal, verify_ml_dsa44, verify_quorum_certificate,
    verify_view_change_certificate,
};
use activechain_protocol_types::{
    BlockProposal, ChainId, ConsensusBlockRef, ConsensusSnapshot, ConsensusState,
    ConsensusStateError, ConsensusUpgradeAuthorization, ConsensusVoteContext, CryptoSuiteId,
    Digest384, PrincipalId, ProposalJustification, ProtocolSignature, QuorumCertificate,
    TimeoutVote, TransactionId, ValidatorGenesis, ValidatorSet, ValidatorVote,
    ViewChangeCertificate,
};
use activechain_rpc_server::{
    AuthorizedFaucetSettlementAdapter, FaucetError, finalized_coin_cell_records_with_chain_genesis,
};
use activechain_rpc_types::QueryRecord;
use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update},
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

mod cash_state;
pub use cash_state::FinalizedCashSnapshot;
mod asset_state;
pub use asset_state::FinalizedAssetLedgerSnapshot;
mod compliance;
pub use compliance::RegulatedTransferAdmission;
pub mod finalized_block;
pub use finalized_block::{
    CashOnlyFinalizedBlockVerifier, DirectExecutionProofV1, DirectExecutionProofVerifier,
    ExecutionProofVerifier, FinalizedBlock, FinalizedBlockAdmissionError, FinalizedBlockCandidate,
    FinalizedBlockHeader, FinalizedBlockVerifier, GenesisBackedFinalizedBlockVerifier,
    PreparedDirectFinalizedBlock, ProofPublicInputs, VerifiedExecutionProof,
};
mod pq_session;
pub use pq_session::{PqPeerSession, PqSessionContext, PqSessionStore, SESSION_TTL_SECS};
mod proof_pipeline;
pub use proof_pipeline::{DurableFinalizedState, DurableProofPipeline, ProofPipelineError};
mod proof_liveness;
pub use proof_liveness::{
    MAX_PROOF_DEADLINE_ROUNDS, MAX_PROOF_GRACE_DEPTH, ProofEvidence, ProofLivenessDecision,
    ProofLivenessError, ProofLivenessInput, ProofLivenessProfile,
};

/// Canonical wallet transaction admission owned by the validator runtime.
/// Authenticated network handlers can delegate here after peer/session checks.
#[derive(Clone)]
pub struct WalletTransactionGateway {
    ingress: activechain_wallet_core::TransactionIngress,
    snapshot_path: std::path::PathBuf,
}

/// Unpublished all-or-nothing cash successor bound to its exact durable pre-state.
pub struct PreparedWalletTransactionBatch {
    pre_ledger: activechain_cash_kernel::CashLedger,
    next: WalletTransactionGateway,
    action_ids: Vec<TransactionId>,
}

impl PreparedWalletTransactionBatch {
    pub fn ledger(&self) -> &activechain_cash_kernel::CashLedger {
        self.next.ledger()
    }
    pub fn pre_cash_cell_root(&self) -> Digest384 {
        activechain_cash_kernel::authenticated_coin_cell_root(self.pre_ledger.cells())
            .expect("prepared invariant-checked pre-state has an authenticated root")
            .into_digest()
    }
    pub fn post_cash_cell_root(&self) -> Digest384 {
        activechain_cash_kernel::authenticated_coin_cell_root(self.next.ledger().cells())
            .expect("prepared invariant-checked post-state has an authenticated root")
            .into_digest()
    }
    pub fn action_ids(&self) -> &[TransactionId] {
        &self.action_ids
    }
    pub fn encoded_ingress_snapshot(
        &self,
    ) -> Result<Vec<u8>, activechain_canonical_codec::EncodeError> {
        activechain_canonical_codec::encode_envelope(&self.next.ingress)
    }
}

impl WalletTransactionGateway {
    pub fn encoded_ingress_snapshot(
        &self,
    ) -> Result<Vec<u8>, activechain_canonical_codec::EncodeError> {
        activechain_canonical_codec::encode_envelope(&self.ingress)
    }

    /// Restores the authenticated wallet ledger and authorization lanes from a durable snapshot.
    pub fn load_snapshot(
        path: &std::path::Path,
        expected_chain: ChainId,
    ) -> Result<Self, activechain_wallet_core::WalletError> {
        Ok(Self {
            ingress: activechain_wallet_core::TransactionIngress::load(path, expected_chain)?,
            snapshot_path: path.to_path_buf(),
        })
    }

    pub fn save_snapshot(
        &self,
        path: &std::path::Path,
    ) -> Result<(), activechain_wallet_core::WalletError> {
        self.ingress.save_atomic(path)
    }

    pub fn from_genesis(
        economy: &activechain_cash_kernel::GenesisEconomy,
        snapshot_path: std::path::PathBuf,
    ) -> Result<Self, activechain_cash_kernel::CashTransitionError> {
        Ok(Self {
            ingress: activechain_wallet_core::TransactionIngress::from_genesis(economy)?,
            snapshot_path,
        })
    }

    pub fn from_ledger(
        ledger: activechain_cash_kernel::CashLedger,
        snapshot_path: std::path::PathBuf,
    ) -> Result<Self, activechain_cash_kernel::CashTransitionError> {
        Ok(Self {
            ingress: activechain_wallet_core::TransactionIngress::from_ledger(ledger)?,
            snapshot_path,
        })
    }

    pub fn submit_envelope(
        &mut self,
        envelope: &[u8],
        height: u64,
    ) -> Result<(), activechain_wallet_core::WalletError> {
        self.ingress.submit_envelope_durable(envelope, height, &self.snapshot_path)
    }

    /// Applies a complete ordered batch to a clone without publishing any state.
    pub fn prepare_envelope_batch(
        &self,
        envelopes: &[Vec<u8>],
        height: u64,
    ) -> Result<PreparedWalletTransactionBatch, activechain_wallet_core::WalletError> {
        let mut next = self.clone();
        let mut action_ids = Vec::with_capacity(envelopes.len());
        next.ingress.prune_replay_state(height);
        for envelope in envelopes {
            let authorized =
                decode_envelope::<activechain_wallet_core::AuthorizedCashTransferV1>(envelope)
                    .map_err(|_| activechain_wallet_core::WalletError::MalformedAuthorization)?;
            let transaction = TransactionId::new(
                authorized
                    .request()
                    .intent_id()
                    .map_err(|_| activechain_wallet_core::WalletError::MalformedAuthorization)?,
            );
            if self.ingress.transaction_admitted(transaction) {
                continue;
            }
            next.ingress.submit_envelope(envelope, height)?;
            action_ids.push(transaction);
        }
        Ok(PreparedWalletTransactionBatch { pre_ledger: self.ledger().clone(), next, action_ids })
    }

    /// Durably publishes a previously prepared batch after consensus certifies its exact root.
    pub fn commit_prepared(
        &mut self,
        prepared: PreparedWalletTransactionBatch,
    ) -> Result<(), activechain_wallet_core::WalletError> {
        if prepared.next.snapshot_path != self.snapshot_path
            || prepared.pre_ledger != *self.ledger()
        {
            return Err(activechain_wallet_core::WalletError::Persistence);
        }
        prepared.next.ingress.save_atomic(&self.snapshot_path)?;
        *self = prepared.next;
        Ok(())
    }

    /// Admits a faucet settlement only when the caller presents the exact
    /// pre-signed cash intent that the faucet approved.
    ///
    /// The durable faucet keeps its request reference mapped to the returned canonical cash
    /// transaction identifier. This boundary independently requires the exact recipient and
    /// amount before the underlying ingress performs signature, nonce, session, input, height,
    /// and Coin Cell conservation checks.
    pub fn submit_faucet_authorized_envelope(
        &mut self,
        envelope: &[u8],
        faucet_reference: Digest384,
        recipient: PrincipalId,
        amount: u128,
        height: u64,
    ) -> Result<TransactionId, activechain_wallet_core::WalletError> {
        let authorized =
            decode_envelope::<activechain_wallet_core::AuthorizedCashTransferV1>(envelope)
                .map_err(|_| activechain_wallet_core::WalletError::MalformedAuthorization)?;
        let request = authorized.request();
        let transaction = request
            .intent_id()
            .map_err(|_| activechain_wallet_core::WalletError::MalformedAuthorization)?;
        if request.transfer().recipient() != recipient
            || request.transfer().amount() != amount
            || request.settlement_reference() != Some(faucet_reference)
            || height > request.transfer().valid_until()
        {
            return Err(activechain_wallet_core::WalletError::PolicyDenied);
        }
        let transaction = TransactionId::new(transaction);
        if self.ingress.transaction_admitted(transaction) {
            return Ok(transaction);
        }
        self.ingress.submit_envelope_durable(envelope, height, &self.snapshot_path)?;
        Ok(transaction)
    }

    /// Registers one sender's finalized ML-DSA-44 cash-session key and initial nonce.
    ///
    /// The caller is responsible for deriving this mapping from finalized identity and
    /// authorization state; the gateway never accepts a key from a transaction request.
    pub fn install_finalized_authorization_key<
        V: activechain_wallet_core::FinalizedIdentityKeyVerifier,
    >(
        &mut self,
        proof: &activechain_wallet_core::FinalizedIdentityKeyProof,
        initial_nonce: u64,
        verifier: &V,
    ) -> Result<(), activechain_wallet_core::WalletError> {
        self.ingress.install_finalized_authorization_key_durable(
            proof,
            initial_nonce,
            verifier,
            &self.snapshot_path,
        )
    }

    pub fn register_session(
        &mut self,
        grant: &activechain_wallet_core::AuthorizedCashSessionGrantV1,
        finalized_height: u64,
    ) -> Result<(), activechain_wallet_core::WalletError> {
        self.ingress.register_session_durable(grant, finalized_height, &self.snapshot_path)
    }

    /// Commits a deterministic native-economics settlement through the same crash-atomic state
    /// boundary as cash admission. Consensus callers cannot mutate the ledger around this gate.
    pub fn settle_epoch_durable(
        &mut self,
        mint: Option<&activechain_cash_kernel::CoinMintTransition>,
        settlement: &activechain_cash_kernel::EpochEconomicsTransition,
    ) -> Result<Option<activechain_protocol_types::CoinCellId>, activechain_wallet_core::WalletError>
    {
        self.ingress.settle_epoch_durable(mint, settlement, &self.snapshot_path)
    }

    pub fn ledger(&self) -> &activechain_cash_kernel::CashLedger {
        self.ingress.ledger()
    }

    /// Returns the currently admitted cells owned by `owner` in canonical order.
    ///
    /// This is an in-process ledger view only. It is intentionally not exposed as a
    /// finalized RPC balance until the validator snapshot persists and authenticates
    /// the same ledger state.
    pub fn owner_cells(
        &self,
        owner: PrincipalId,
    ) -> Result<activechain_cash_kernel::CoinCellSet, activechain_cash_kernel::NativeMoneyError>
    {
        activechain_cash_kernel::CoinCellSet::new(
            self.ledger()
                .cells()
                .as_slice()
                .iter()
                .filter(|record| record.cell().owner() == owner)
                .cloned()
                .collect(),
        )
    }

    /// Materializes the admitted cash ledger as an execution snapshot. The caller must still
    /// authenticate this snapshot against the finalized block certificate before publishing it
    /// through `ValidatorService::finalized_cash_rpc_records`.
    pub fn finalized_cash_snapshot(
        &self,
        chain_genesis: Digest384,
        finalized_height: u64,
    ) -> Result<FinalizedCashSnapshot, &'static str> {
        FinalizedCashSnapshot::new(chain_genesis, finalized_height, self.ledger().cells().clone())
    }
}

/// Validator-owned adapter that connects the RPC authorized-faucet boundary
/// to the real authenticated transaction ingress. The finalized height is
/// supplied by the consensus service and is never taken from the RPC caller.
pub struct ValidatorFaucetSettlementAdapter {
    gateway: Arc<Mutex<WalletTransactionGateway>>,
    finalized_height: Arc<AtomicU64>,
}

impl ValidatorFaucetSettlementAdapter {
    pub fn new(
        gateway: Arc<Mutex<WalletTransactionGateway>>,
        finalized_height: Arc<AtomicU64>,
    ) -> Self {
        Self { gateway, finalized_height }
    }

    pub fn set_finalized_height(&self, height: u64) {
        self.finalized_height.store(height, Ordering::Release);
    }
}

impl AuthorizedFaucetSettlementAdapter for ValidatorFaucetSettlementAdapter {
    fn settle_authorized(
        &self,
        envelope: &[u8],
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError> {
        let height = self.finalized_height.load(Ordering::Acquire);
        let mut gateway = self.gateway.lock().map_err(|_| FaucetError::Persistence)?;
        gateway
            .submit_faucet_authorized_envelope(envelope, reference, recipient, amount, height)
            .map_err(|error| match error {
                activechain_wallet_core::WalletError::Persistence => FaucetError::Persistence,
                _ => FaucetError::InvalidTransition,
            })
    }
}

const PEER_BODY_DOMAIN: &[u8] = b"ACTIVECHAIN-PEER-BODY-V1";
pub const MAX_PEER_FRAME_LEN: usize = 32 * 1024;
pub const PEER_FRAME_DEADLINE: Duration = Duration::from_secs(5);
pub const PEER_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const PEER_SESSION_LIFETIME: Duration = Duration::from_secs(5 * 60);
pub const MAX_PEER_SESSION_MESSAGES: usize = 4096;
pub const MAX_AUTHENTICATED_MESSAGES_PER_SECOND: usize = 256;
pub const MAX_PEER_INGRESS_WORKERS: usize = 64;
pub const MAX_PEER_INGRESS_QUEUE: usize = 1024;
pub const MAX_PRE_AUTH_PER_SOURCE_PER_SECOND: usize = 4096;
pub const MAX_TRACKED_INGRESS_SOURCES: usize = 8192;

#[derive(Default)]
pub struct ValidatorMetrics {
    proposals: AtomicU64,
    votes: AtomicU64,
    finalized_certificates: AtomicU64,
    rejected_messages: AtomicU64,
    peer_sessions_established: AtomicU64,
    peer_session_rejections: AtomicU64,
    peer_rate_limited: AtomicU64,
    peer_timeouts: AtomicU64,
    peer_malformed_frames: AtomicU64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricsSnapshot {
    pub proposals: u64,
    pub votes: u64,
    pub finalized_certificates: u64,
    pub rejected_messages: u64,
    pub peer_sessions_established: u64,
    pub peer_session_rejections: u64,
    pub peer_rate_limited: u64,
    pub peer_timeouts: u64,
    pub peer_malformed_frames: u64,
}
impl MetricsSnapshot {
    pub fn prometheus(self, validator_id: u16) -> String {
        format!(
            "activechain_validator_proposals{{validator=\"{validator_id}\"}} {}\nactivechain_validator_votes{{validator=\"{validator_id}\"}} {}\nactivechain_validator_finalized_certificates{{validator=\"{validator_id}\"}} {}\nactivechain_validator_rejected_messages{{validator=\"{validator_id}\"}} {}\nactivechain_validator_peer_sessions_established{{validator=\"{validator_id}\"}} {}\nactivechain_validator_peer_session_rejections{{validator=\"{validator_id}\"}} {}\nactivechain_validator_peer_rate_limited{{validator=\"{validator_id}\"}} {}\nactivechain_validator_peer_timeouts{{validator=\"{validator_id}\"}} {}\nactivechain_validator_peer_malformed_frames{{validator=\"{validator_id}\"}} {}\n",
            self.proposals,
            self.votes,
            self.finalized_certificates,
            self.rejected_messages,
            self.peer_sessions_established,
            self.peer_session_rejections,
            self.peer_rate_limited,
            self.peer_timeouts,
            self.peer_malformed_frames,
        )
    }
}
impl ValidatorMetrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            proposals: self.proposals.load(Ordering::Relaxed),
            votes: self.votes.load(Ordering::Relaxed),
            finalized_certificates: self.finalized_certificates.load(Ordering::Relaxed),
            rejected_messages: self.rejected_messages.load(Ordering::Relaxed),
            peer_sessions_established: self.peer_sessions_established.load(Ordering::Relaxed),
            peer_session_rejections: self.peer_session_rejections.load(Ordering::Relaxed),
            peer_rate_limited: self.peer_rate_limited.load(Ordering::Relaxed),
            peer_timeouts: self.peer_timeouts.load(Ordering::Relaxed),
            peer_malformed_frames: self.peer_malformed_frames.load(Ordering::Relaxed),
        }
    }
}

pub struct ValidatorSigner {
    validator: activechain_protocol_types::PrincipalId,
    key: SigningKey<MlDsa44>,
}

const VALIDATOR_KEY_FILE_MAGIC: &[u8; 8] = b"ACVKEY01";
const VALIDATOR_KEY_FILE_LEN: usize = VALIDATOR_KEY_FILE_MAGIC.len() + 32;

#[derive(Debug)]
pub enum ValidatorKeyFileError {
    Io(std::io::Error),
    InvalidPermissions,
    InvalidEncoding,
    LegacyDeterministicKey,
    ManifestMismatch,
    Randomness,
}

impl std::fmt::Display for ValidatorKeyFileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ValidatorKeyFileError {}

impl From<std::io::Error> for ValidatorKeyFileError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

fn validator_principal(public_key: &[u8]) -> PrincipalId {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-VALIDATOR-PUBLIC-KEY-ID-V1");
    hasher.update(public_key);
    let mut digest = [0_u8; 48];
    sha3::digest::XofReader::read(&mut hasher.finalize_xof(), &mut digest);
    PrincipalId::new(Digest384::new(digest))
}

/// Creates one exclusive, owner-only validator seed file from operating-system randomness.
#[cfg(unix)]
pub fn provision_validator_key(
    path: &std::path::Path,
) -> Result<(PrincipalId, Vec<u8>), ValidatorKeyFileError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|_| ValidatorKeyFileError::Randomness)?;
    let signer = ValidatorSigner::from_seed(PrincipalId::new(Digest384::ZERO), seed);
    let public_key = signer.public_key();
    let principal = validator_principal(&public_key);
    let mut file =
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(VALIDATOR_KEY_FILE_MAGIC)?;
    file.write_all(&seed)?;
    file.sync_all()?;
    seed.zeroize();
    Ok((principal, public_key))
}

#[cfg(not(unix))]
pub fn provision_validator_key(
    _path: &std::path::Path,
) -> Result<(PrincipalId, Vec<u8>), ValidatorKeyFileError> {
    Err(ValidatorKeyFileError::InvalidPermissions)
}

impl ValidatorSigner {
    /// Loads an owner-only validator key and proves it is neither a legacy deterministic key nor
    /// a key belonging to a different manifest entry.
    #[cfg(unix)]
    pub fn from_key_file(
        path: &std::path::Path,
        genesis: &ValidatorGenesis,
        entry: &activechain_protocol_types::ValidatorGenesisEntry,
    ) -> Result<Self, ValidatorKeyFileError> {
        use std::io::Read as _;
        use std::os::unix::fs::MetadataExt as _;

        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let mut file = std::fs::File::from(descriptor);
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.nlink() != 1
        {
            return Err(ValidatorKeyFileError::InvalidPermissions);
        }
        let mut bytes = Vec::with_capacity(VALIDATOR_KEY_FILE_LEN);
        file.read_to_end(&mut bytes)?;
        if bytes.len() != VALIDATOR_KEY_FILE_LEN
            || &bytes[..VALIDATOR_KEY_FILE_MAGIC.len()] != VALIDATOR_KEY_FILE_MAGIC
        {
            bytes.zeroize();
            return Err(ValidatorKeyFileError::InvalidEncoding);
        }
        let mut seed: [u8; 32] = bytes[VALIDATOR_KEY_FILE_MAGIC.len()..]
            .try_into()
            .map_err(|_| ValidatorKeyFileError::InvalidEncoding)?;
        bytes.zeroize();
        for candidate in 0..activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH {
            let mut legacy = [0_u8; 32];
            legacy[..8].copy_from_slice(&(candidate as u64).to_be_bytes());
            legacy[8..16].copy_from_slice(&genesis.epoch().to_be_bytes());
            legacy[16..24].copy_from_slice(&genesis.activation_height().to_be_bytes());
            if seed == legacy {
                seed.zeroize();
                legacy.zeroize();
                return Err(ValidatorKeyFileError::LegacyDeterministicKey);
            }
            legacy.zeroize();
        }
        let signer = Self::from_seed(entry.validator(), seed);
        seed.zeroize();
        if signer.public_key().as_slice() != entry.public_key()
            || validator_principal(entry.public_key()) != entry.validator()
        {
            return Err(ValidatorKeyFileError::ManifestMismatch);
        }
        Ok(signer)
    }

    #[cfg(not(unix))]
    pub fn from_key_file(
        _path: &std::path::Path,
        _genesis: &ValidatorGenesis,
        _entry: &activechain_protocol_types::ValidatorGenesisEntry,
    ) -> Result<Self, ValidatorKeyFileError> {
        Err(ValidatorKeyFileError::InvalidPermissions)
    }
}
impl ValidatorSigner {
    pub fn from_seed(validator: activechain_protocol_types::PrincipalId, seed: [u8; 32]) -> Self {
        Self { validator, key: SigningKey::<MlDsa44>::from_seed(&Seed::from(seed)) }
    }
    pub const fn validator(&self) -> activechain_protocol_types::PrincipalId {
        self.validator
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().encode().to_vec()
    }
    fn sign_session_payload(&self, payload: &[u8]) -> Vec<u8> {
        self.key.sign(payload).encode().to_vec()
    }
    fn sign_vote(
        &self,
        proposal: &BlockProposal,
        genesis_commitment: Digest384,
        validator_set_root: Digest384,
        protocol_revision: u64,
    ) -> Result<ValidatorVote, ValidatorEngineError> {
        let context = ConsensusVoteContext::new_with_revision(
            genesis_commitment,
            proposal.epoch(),
            validator_set_root,
            protocol_revision,
        )
        .map_err(|_| ValidatorEngineError::UnboundConsensusDomain)?;
        let proposal_commitment = proposal.commitment();
        let unsigned = ValidatorVote::new(
            self.validator,
            context,
            proposal.height(),
            proposal.round(),
            proposal.block_digest(),
            proposal_commitment,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)?;
        let signature = self.key.sign(&unsigned.signing_payload());
        ValidatorVote::new(
            self.validator,
            context,
            proposal.height(),
            proposal.round(),
            proposal.block_digest(),
            proposal_commitment,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)
    }
    fn sign_proposal(
        &self,
        context: ConsensusVoteContext,
        height: u64,
        round: u64,
        block_digest: Digest384,
        justification: ProposalJustification,
    ) -> Result<BlockProposal, ValidatorEngineError> {
        let unsigned = BlockProposal::new(
            self.validator,
            context,
            height,
            round,
            block_digest,
            justification.clone(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)?;
        let signature = self.key.sign(&unsigned.signing_payload());
        BlockProposal::new(
            self.validator,
            context,
            height,
            round,
            block_digest,
            justification,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)
    }
    fn sign_timeout_vote(
        &self,
        context: ConsensusVoteContext,
        height: u64,
        round: u64,
        parent: ConsensusBlockRef,
        highest_qc: Option<QuorumCertificate>,
    ) -> Result<TimeoutVote, ValidatorEngineError> {
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
            .map_err(|_| ValidatorEngineError::Signer)?;
        let unsigned = TimeoutVote::new(
            self.validator,
            context,
            height,
            round,
            parent,
            highest_qc.clone(),
            placeholder,
        )
        .map_err(|_| ValidatorEngineError::InvalidViewChange)?;
        let signature = self.key.sign(&unsigned.signing_payload());
        TimeoutVote::new(
            self.validator,
            context,
            height,
            round,
            parent,
            highest_qc,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::InvalidViewChange)
    }
    fn sign_envelope(
        &self,
        sender: u16,
        sequence: u64,
        message: ConsensusMessage,
    ) -> Result<AuthenticatedConsensusMessage, ValidatorEngineError> {
        let digest = message.digest().map_err(ValidatorEngineError::Transport)?;
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420])
            .map_err(|_| ValidatorEngineError::Signer)?;
        let unsigned = SignedPeerEnvelope::new(sender, sequence, digest, placeholder)
            .map_err(|_| ValidatorEngineError::Signer)?;
        let signature = self.key.sign(&unsigned.signing_payload());
        let envelope = SignedPeerEnvelope::new(
            sender,
            sequence,
            digest,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                .map_err(|_| ValidatorEngineError::Signer)?,
        )
        .map_err(|_| ValidatorEngineError::Signer)?;
        AuthenticatedConsensusMessage::new(envelope, message)
            .map_err(ValidatorEngineError::Transport)
    }
}

#[derive(Clone)]
struct PreparedValidatorVote {
    proposal: BlockProposal,
    genesis_commitment: Digest384,
    validator_set_root: Digest384,
    protocol_revision: u64,
}

#[derive(Clone)]
struct PreparedTimeoutVote {
    context: ConsensusVoteContext,
    height: u64,
    round: u64,
    parent: ConsensusBlockRef,
    highest_qc: Option<QuorumCertificate>,
}

/// Internal signing boundary used to prove that durable safety state precedes key use.
trait ConsensusVoteSigner {
    fn validator(&self) -> PrincipalId;
    fn sign_prepared_vote(
        &self,
        prepared: &PreparedValidatorVote,
    ) -> Result<ValidatorVote, ValidatorEngineError>;
}

impl ConsensusVoteSigner for ValidatorSigner {
    fn validator(&self) -> PrincipalId {
        self.validator
    }

    fn sign_prepared_vote(
        &self,
        prepared: &PreparedValidatorVote,
    ) -> Result<ValidatorVote, ValidatorEngineError> {
        self.sign_vote(
            &prepared.proposal,
            prepared.genesis_commitment,
            prepared.validator_set_root,
            prepared.protocol_revision,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedBlock {
    proposal: BlockProposal,
    certificate: QuorumCertificate,
    votes: Vec<ValidatorVote>,
}
impl CertifiedBlock {
    pub fn new(
        proposal: BlockProposal,
        certificate: QuorumCertificate,
        votes: Vec<ValidatorVote>,
    ) -> Result<Self, TransportError> {
        if votes.is_empty() || votes.len() > activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH {
            return Err(TransportError::InvalidBody);
        }
        let vote_domain = (
            votes[0].genesis_commitment(),
            votes[0].validator_set_root(),
            votes[0].protocol_revision(),
        );
        let proposal_commitment = proposal.commitment();
        if certificate.genesis_commitment() != proposal.genesis_commitment()
            || certificate.epoch() != proposal.epoch()
            || certificate.validator_set_root() != proposal.validator_set_root()
            || certificate.protocol_revision() != proposal.protocol_revision()
            || certificate.height() != proposal.height()
            || certificate.round() != proposal.round()
            || certificate.block_digest() != proposal.block_digest()
            || certificate.proposal_commitment() != proposal_commitment
            || votes.iter().any(|vote| {
                vote.genesis_commitment() != certificate.genesis_commitment()
                    || vote.epoch() != certificate.epoch()
                    || vote.validator_set_root() != certificate.validator_set_root()
                    || vote.protocol_revision() != certificate.protocol_revision()
                    || (
                        vote.genesis_commitment(),
                        vote.validator_set_root(),
                        vote.protocol_revision(),
                    ) != vote_domain
                    || vote.height() != certificate.height()
                    || vote.round() != certificate.round()
                    || vote.block_digest() != certificate.block_digest()
                    || vote.proposal_commitment() != proposal_commitment
            })
        {
            return Err(TransportError::InvalidBody);
        }
        Ok(Self { proposal, certificate, votes })
    }
    pub const fn proposal(&self) -> &BlockProposal {
        &self.proposal
    }
    pub const fn certificate(&self) -> &QuorumCertificate {
        &self.certificate
    }
    pub fn votes(&self) -> &[ValidatorVote] {
        &self.votes
    }
    fn encode(&self) -> Result<Vec<u8>, TransportError> {
        let proposal = encode_envelope(&self.proposal).map_err(|_| TransportError::InvalidBody)?;
        let certificate =
            encode_envelope(&self.certificate).map_err(|_| TransportError::InvalidBody)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(proposal.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&proposal);
        bytes.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&certificate);
        bytes.extend_from_slice(&(self.votes.len() as u16).to_be_bytes());
        for vote in &self.votes {
            let encoded = encode_envelope(vote).map_err(|_| TransportError::InvalidBody)?;
            bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        Ok(bytes)
    }
    fn decode(mut bytes: &[u8]) -> Result<Self, TransportError> {
        let proposal_bytes = take_length_prefixed(&mut bytes)?;
        let proposal = decode_envelope(proposal_bytes).map_err(|_| TransportError::InvalidBody)?;
        let certificate_bytes = take_length_prefixed(&mut bytes)?;
        let certificate =
            decode_envelope(certificate_bytes).map_err(|_| TransportError::InvalidBody)?;
        if bytes.len() < 2 {
            return Err(TransportError::InvalidBody);
        }
        let count = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        bytes = &bytes[2..];
        if count == 0 || count > activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH {
            return Err(TransportError::InvalidBody);
        }
        let mut votes = Vec::with_capacity(count);
        for _ in 0..count {
            votes.push(
                decode_envelope(take_length_prefixed(&mut bytes)?)
                    .map_err(|_| TransportError::InvalidBody)?,
            );
        }
        if !bytes.is_empty() {
            return Err(TransportError::InvalidBody);
        }
        Self::new(proposal, certificate, votes)
    }
}

fn take_length_prefixed<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], TransportError> {
    if bytes.len() < 4 {
        return Err(TransportError::InvalidBody);
    }
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if length > MAX_PEER_FRAME_LEN || bytes.len() < 4 + length {
        return Err(TransportError::InvalidBody);
    }
    let value = &bytes[4..4 + length];
    *bytes = &bytes[4 + length..];
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ConsensusMessage {
    Proposal(BlockProposal),
    Vote(ValidatorVote),
    Certificate(CertifiedBlock),
    CertifiedBlockRequest(Digest384),
    TimeoutVote(TimeoutVote),
    ViewChange(ViewChangeCertificate),
}
impl ConsensusMessage {
    fn kind(&self) -> u8 {
        match self {
            Self::Proposal(_) => 1,
            Self::Vote(_) => 2,
            Self::Certificate(_) => 3,
            Self::CertifiedBlockRequest(_) => 4,
            Self::TimeoutVote(_) => 5,
            Self::ViewChange(_) => 6,
        }
    }
    fn encode_body(&self) -> Result<Vec<u8>, TransportError> {
        match self {
            Self::Proposal(value) => encode_envelope(value),
            Self::Vote(value) => encode_envelope(value),
            Self::Certificate(value) => return value.encode(),
            Self::CertifiedBlockRequest(commitment) => return Ok(commitment.as_bytes().to_vec()),
            Self::TimeoutVote(value) => encode_envelope(value),
            Self::ViewChange(value) => encode_envelope(value),
        }
        .map_err(|_| TransportError::InvalidBody)
    }
    fn decode(kind: u8, body: &[u8]) -> Result<Self, TransportError> {
        match kind {
            1 => decode_envelope(body).map(Self::Proposal),
            2 => decode_envelope(body).map(Self::Vote),
            3 => return CertifiedBlock::decode(body).map(Self::Certificate),
            4 if body.len() == 48 => {
                return Ok(Self::CertifiedBlockRequest(Digest384::new(
                    body.try_into().map_err(|_| TransportError::InvalidBody)?,
                )));
            }
            5 => decode_envelope(body).map(Self::TimeoutVote),
            6 => decode_envelope(body).map(Self::ViewChange),
            _ => return Err(TransportError::InvalidMessageKind),
        }
        .map_err(|_| TransportError::InvalidBody)
    }
    pub fn digest(&self) -> Result<Digest384, TransportError> {
        let body = self.encode_body()?;
        let mut hasher = Shake256::default();
        hasher.update(PEER_BODY_DOMAIN);
        hasher.update(&[self.kind()]);
        hasher.update(&(body.len() as u32).to_be_bytes());
        hasher.update(&body);
        let mut digest = [0_u8; 48];
        sha3::digest::XofReader::read(&mut hasher.finalize_xof(), &mut digest);
        Ok(Digest384::new(digest))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedConsensusMessage {
    pub envelope: SignedPeerEnvelope,
    pub message: ConsensusMessage,
}
impl AuthenticatedConsensusMessage {
    pub fn new(
        envelope: SignedPeerEnvelope,
        message: ConsensusMessage,
    ) -> Result<Self, TransportError> {
        if envelope.body_digest() != message.digest()? {
            return Err(TransportError::BodyDigestMismatch);
        }
        Ok(Self { envelope, message })
    }
    fn wire_bytes(&self) -> std::io::Result<Vec<u8>> {
        let body = self.message.encode_body().map_err(transport_io_error)?;
        let envelope = &self.envelope;
        let frame_len = 2 + 8 + 48 + 2 + envelope.signature_bytes().len() + 1 + 4 + body.len();
        if frame_len > MAX_PEER_FRAME_LEN {
            return Err(invalid_data("peer frame exceeds limit"));
        }
        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(&envelope.sender().to_be_bytes());
        frame.extend_from_slice(&envelope.sequence().to_be_bytes());
        frame.extend_from_slice(envelope.body_digest().as_bytes());
        frame.extend_from_slice(&(envelope.signature_bytes().len() as u16).to_be_bytes());
        frame.extend_from_slice(envelope.signature_bytes());
        frame.push(self.message.kind());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame)
    }
    fn from_wire_bytes(frame: &[u8]) -> std::io::Result<Self> {
        if frame.len() < 65 {
            return Err(invalid_data("consensus frame too short"));
        }
        let sender = u16::from_be_bytes([frame[0], frame[1]]);
        let sequence = u64::from_be_bytes(frame[2..10].try_into().unwrap());
        let digest = Digest384::new(frame[10..58].try_into().unwrap());
        let signature_len = u16::from_be_bytes([frame[58], frame[59]]) as usize;
        let kind_offset = 60_usize
            .checked_add(signature_len)
            .ok_or_else(|| invalid_data("invalid signature length"))?;
        let body_offset = kind_offset + 5;
        if body_offset > frame.len() {
            return Err(invalid_data("truncated consensus frame"));
        }
        let body_len =
            u32::from_be_bytes(frame[kind_offset + 1..body_offset].try_into().unwrap()) as usize;
        if frame.len() != body_offset + body_len {
            return Err(invalid_data("consensus body length mismatch"));
        }
        let signature =
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, frame[60..kind_offset].to_vec())
                .map_err(|_| invalid_data("invalid ML-DSA signature"))?;
        let envelope = SignedPeerEnvelope::new(sender, sequence, digest, signature)
            .map_err(transport_io_error)?;
        let message = ConsensusMessage::decode(frame[kind_offset], &frame[body_offset..])
            .map_err(transport_io_error)?;
        Self::new(envelope, message).map_err(transport_io_error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPeerEnvelope {
    sender: u16,
    sequence: u64,
    body_digest: Digest384,
    signature: ProtocolSignature,
}

impl SignedPeerEnvelope {
    pub fn new(
        sender: u16,
        sequence: u64,
        body_digest: Digest384,
        signature: ProtocolSignature,
    ) -> Result<Self, TransportError> {
        if signature.suite() != CryptoSuiteId::ML_DSA_44 {
            return Err(TransportError::InvalidSuite);
        }
        Ok(Self { sender, sequence, body_digest, signature })
    }
    pub const fn sender(&self) -> u16 {
        self.sender
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn body_digest(&self) -> Digest384 {
        self.body_digest
    }
    pub fn signature_bytes(&self) -> &[u8] {
        self.signature.as_bytes()
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(18 + 2 + 8 + 48);
        bytes.extend_from_slice(b"ACTIVECHAIN-PEER-V1");
        bytes.extend_from_slice(&self.sender.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(self.body_digest.as_bytes());
        bytes
    }
    pub fn verify(&self, public_key: &[u8]) -> Result<(), TransportError> {
        activechain_crypto_provider::verify_ml_dsa44(
            public_key,
            &self.signing_payload(),
            self.signature.as_bytes(),
        )
        .map_err(TransportError::Verification)
    }
}

pub struct PeerSocket {
    stream: TcpStream,
    absolute_deadline: Option<Instant>,
    session_messages: usize,
}

struct PeerConnection {
    socket: PeerSocket,
    public_key: Vec<u8>,
    session: PqPeerSession,
}

pub struct PeerDirectory {
    peers: BTreeMap<u16, PeerConnection>,
    replay: ReplayGuard,
    rate_limits: BTreeMap<u16, (Instant, usize)>,
    session_store: Arc<Mutex<PqSessionStore>>,
    session_store_path: std::path::PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIngressConfig {
    pub workers: usize,
    pub queue_capacity: usize,
    pub pre_auth_per_source_per_second: usize,
    pub max_tracked_sources: usize,
}

impl Default for PeerIngressConfig {
    fn default() -> Self {
        Self {
            workers: 16,
            queue_capacity: 64,
            pre_auth_per_source_per_second: 32,
            max_tracked_sources: 1024,
        }
    }
}

#[derive(Default)]
struct PeerIngressMetrics {
    accepted: AtomicU64,
    active: AtomicU64,
    queued: AtomicU64,
    shed: AtomicU64,
    pre_auth_rate_limited: AtomicU64,
    recovered: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PeerIngressMetricsSnapshot {
    pub accepted: u64,
    pub active: u64,
    pub queued: u64,
    pub shed: u64,
    pub pre_auth_rate_limited: u64,
    pub recovered: u64,
}

impl PeerIngressMetricsSnapshot {
    pub fn prometheus(self, validator_id: u16) -> String {
        format!(
            "activechain_peer_ingress_accepted{{validator=\"{validator_id}\"}} {}\nactivechain_peer_ingress_active{{validator=\"{validator_id}\"}} {}\nactivechain_peer_ingress_queued{{validator=\"{validator_id}\"}} {}\nactivechain_peer_ingress_shed{{validator=\"{validator_id}\"}} {}\nactivechain_peer_ingress_pre_auth_rate_limited{{validator=\"{validator_id}\"}} {}\nactivechain_peer_ingress_recovered{{validator=\"{validator_id}\"}} {}\n",
            self.accepted,
            self.active,
            self.queued,
            self.shed,
            self.pre_auth_rate_limited,
            self.recovered,
        )
    }
}

#[derive(Clone)]
pub struct PeerIngressMonitor {
    metrics: Arc<PeerIngressMetrics>,
}

impl PeerIngressMonitor {
    pub fn snapshot(&self) -> PeerIngressMetricsSnapshot {
        self.metrics.snapshot()
    }
}

impl PeerIngressMetrics {
    fn snapshot(&self) -> PeerIngressMetricsSnapshot {
        PeerIngressMetricsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            queued: self.queued.load(Ordering::Relaxed),
            shed: self.shed.load(Ordering::Relaxed),
            pre_auth_rate_limited: self.pre_auth_rate_limited.load(Ordering::Relaxed),
            recovered: self.recovered.load(Ordering::Relaxed),
        }
    }
}

pub struct PeerListener {
    listener: TcpListener,
    config: PeerIngressConfig,
    metrics: Arc<PeerIngressMetrics>,
}
impl PeerListener {
    pub fn bind(address: (&str, u16)) -> std::io::Result<Self> {
        Self::bind_with_config(address, PeerIngressConfig::default())
    }
    pub fn bind_with_config(
        address: (&str, u16),
        config: PeerIngressConfig,
    ) -> std::io::Result<Self> {
        if config.workers == 0
            || config.workers > MAX_PEER_INGRESS_WORKERS
            || config.queue_capacity == 0
            || config.queue_capacity > MAX_PEER_INGRESS_QUEUE
            || config.pre_auth_per_source_per_second == 0
            || config.pre_auth_per_source_per_second > MAX_PRE_AUTH_PER_SOURCE_PER_SECOND
            || config.max_tracked_sources == 0
            || config.max_tracked_sources > MAX_TRACKED_INGRESS_SOURCES
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "peer ingress bounds must be non-zero",
            ));
        }
        Ok(Self {
            listener: TcpListener::bind(address)?,
            config,
            metrics: Arc::new(PeerIngressMetrics::default()),
        })
    }
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
    pub fn accept(&self) -> std::io::Result<PeerSocket> {
        let (stream, _) = self.listener.accept()?;
        Ok(PeerSocket::connect(stream))
    }
    pub fn metrics(&self) -> PeerIngressMetricsSnapshot {
        self.metrics.snapshot()
    }
    pub fn monitor(&self) -> PeerIngressMonitor {
        PeerIngressMonitor { metrics: Arc::clone(&self.metrics) }
    }
    pub fn spawn_accept_loop<F>(&self, handler: F) -> std::io::Result<()>
    where
        F: Fn(PeerSocket) + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let (sender, receiver) = mpsc::sync_channel::<PeerSocket>(self.config.queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..self.config.workers {
            let handler = Arc::clone(&handler);
            let receiver = Arc::clone(&receiver);
            let metrics = Arc::clone(&self.metrics);
            std::thread::spawn(move || {
                loop {
                    let socket = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => return,
                    };
                    let Ok(socket) = socket else { return };
                    metrics.queued.fetch_sub(1, Ordering::Relaxed);
                    metrics.active.fetch_add(1, Ordering::Relaxed);
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handler(socket);
                    }));
                    metrics.active.fetch_sub(1, Ordering::Relaxed);
                    metrics.recovered.fetch_add(1, Ordering::Relaxed);
                    if outcome.is_err() {
                        eprintln!("peer_ingress event=handler_panic worker=recovered");
                    }
                }
            });
        }
        let mut source_windows = BTreeMap::<IpAddr, (Instant, usize)>::new();
        let mut last_source_prune = Instant::now();
        loop {
            let (stream, address) = self.listener.accept()?;
            self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
            let now = Instant::now();
            if now.saturating_duration_since(last_source_prune) >= Duration::from_secs(1) {
                source_windows.retain(|_, (started, _)| {
                    now.saturating_duration_since(*started) < Duration::from_secs(1)
                });
                last_source_prune = now;
            }
            let source = address.ip();
            let allowed = if let Some((started, count)) = source_windows.get_mut(&source) {
                if now.saturating_duration_since(*started) >= Duration::from_secs(1) {
                    *started = now;
                    *count = 1;
                    true
                } else if *count < self.config.pre_auth_per_source_per_second {
                    *count += 1;
                    true
                } else {
                    false
                }
            } else if source_windows.len() < self.config.max_tracked_sources {
                source_windows.insert(source, (now, 1));
                true
            } else {
                false
            };
            if !allowed {
                self.metrics.pre_auth_rate_limited.fetch_add(1, Ordering::Relaxed);
                self.metrics.shed.fetch_add(1, Ordering::Relaxed);
                eprintln!("peer_ingress event=pre_auth_rate_limited source={source}");
                drop(stream);
                continue;
            }
            self.metrics.queued.fetch_add(1, Ordering::Relaxed);
            match sender.try_send(PeerSocket::connect(stream)) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(socket)) => {
                    self.metrics.queued.fetch_sub(1, Ordering::Relaxed);
                    self.metrics.shed.fetch_add(1, Ordering::Relaxed);
                    eprintln!("peer_ingress event=queue_full source={source}");
                    drop(socket);
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    self.metrics.queued.fetch_sub(1, Ordering::Relaxed);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "peer ingress worker queue disconnected",
                    ));
                }
            }
        }
    }
}
impl PeerDirectory {
    pub const MAX_PEERS: usize = 128;
    fn new(
        session_store: Arc<Mutex<PqSessionStore>>,
        session_store_path: std::path::PathBuf,
    ) -> Self {
        Self {
            peers: BTreeMap::new(),
            replay: ReplayGuard::default(),
            rate_limits: BTreeMap::new(),
            session_store,
            session_store_path,
        }
    }
    fn insert(
        &mut self,
        peer_id: u16,
        socket: PeerSocket,
        public_key: Vec<u8>,
        session: PqPeerSession,
    ) -> Result<(), PeerDirectoryError> {
        if public_key.len() != 1312 || session.peer != peer_id {
            return Err(PeerDirectoryError::InvalidPublicKey);
        }
        if self.peers.contains_key(&peer_id) {
            return Err(PeerDirectoryError::AlreadyRegistered);
        }
        if self.peers.len() >= Self::MAX_PEERS {
            return Err(PeerDirectoryError::Capacity);
        }
        self.peers.insert(peer_id, PeerConnection { socket, public_key, session });
        Ok(())
    }
    pub fn replace(
        &mut self,
        peer_id: u16,
        socket: PeerSocket,
        public_key: Vec<u8>,
        session: PqPeerSession,
    ) -> Result<(), PeerDirectoryError> {
        if self.peers.contains_key(&peer_id) {
            self.peers.remove(&peer_id);
        }
        self.insert(peer_id, socket, public_key, session)
    }
    pub fn len(&self) -> usize {
        self.peers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
    pub fn peer_ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.peers.keys().copied()
    }
    pub fn remove(&mut self, peer_id: u16) -> bool {
        self.peers.remove(&peer_id).is_some()
    }
    pub fn receive_verified(
        &mut self,
        peer_id: u16,
    ) -> Result<AuthenticatedConsensusMessage, PeerReceiveError> {
        if !self.allow_receive(peer_id, Instant::now()) {
            return Err(PeerReceiveError::Transport(TransportError::RateLimited));
        }
        let connection = self.peers.get_mut(&peer_id).ok_or(PeerReceiveError::UnknownPeer)?;
        let (session_sequence, message) = connection
            .socket
            .receive_protected_message(&connection.session)
            .map_err(PeerReceiveError::Io)?;
        if message.envelope.sender() != peer_id {
            return Err(PeerReceiveError::Transport(TransportError::SenderMismatch));
        }
        self.session_store
            .lock()
            .map_err(|_| PeerReceiveError::Io(invalid_data("PQ session store lock poisoned")))?
            .accept_receive_and_save(
                connection.session.id,
                session_sequence,
                &self.session_store_path,
            )
            .map_err(PeerReceiveError::Io)?;
        self.replay
            .accept(&message.envelope, &connection.public_key)
            .map_err(PeerReceiveError::Transport)?;
        Ok(message)
    }
    fn allow_receive(&mut self, peer_id: u16, now: Instant) -> bool {
        let entry = self.rate_limits.entry(peer_id).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(1) {
            *entry = (now, 0);
        }
        if entry.1 >= MAX_AUTHENTICATED_MESSAGES_PER_SECOND {
            return false;
        }
        entry.1 += 1;
        true
    }
    pub fn broadcast_message(
        &mut self,
        message: &AuthenticatedConsensusMessage,
    ) -> std::io::Result<()> {
        for connection in self.peers.values_mut() {
            let sequence = self
                .session_store
                .lock()
                .map_err(|_| invalid_data("PQ session store lock poisoned"))?
                .reserve_send_and_save(connection.session.id, &self.session_store_path)?;
            connection.socket.send_protected_message(&connection.session, sequence, message)?;
        }
        Ok(())
    }
    pub fn broadcast_message_best_effort(
        &mut self,
        message: &AuthenticatedConsensusMessage,
    ) -> Vec<u16> {
        let mut failed = Vec::new();
        for (peer_id, connection) in &mut self.peers {
            let result = self
                .session_store
                .lock()
                .map_err(|_| invalid_data("PQ session store lock poisoned"))
                .and_then(|mut store| {
                    store.reserve_send_and_save(connection.session.id, &self.session_store_path)
                })
                .and_then(|sequence| {
                    connection.socket.send_protected_message(&connection.session, sequence, message)
                });
            if result.is_err() {
                failed.push(*peer_id);
            }
        }
        for peer_id in &failed {
            self.peers.remove(peer_id);
        }
        failed
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerDirectoryError {
    AlreadyRegistered,
    Capacity,
    InvalidPublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerEndpoint {
    pub id: u16,
    pub address: SocketAddr,
    pub public_key: Vec<u8>,
}
impl PeerEndpoint {
    pub fn from_genesis_address(
        id: u16,
        address: &str,
        public_key: Vec<u8>,
    ) -> Result<Self, PeerConnectorError> {
        if id == 0 || public_key.len() != 1312 {
            return Err(PeerConnectorError::InvalidConfiguration);
        }
        let address = address.parse().map_err(|_| PeerConnectorError::InvalidConfiguration)?;
        Ok(Self { id, address, public_key })
    }
}
pub struct PeerConnector {
    endpoints: Vec<PeerEndpoint>,
    attempts: usize,
    connect_timeout: Duration,
    backoff: Duration,
}
impl PeerConnector {
    pub fn new(endpoints: Vec<PeerEndpoint>) -> Result<Self, PeerConnectorError> {
        if endpoints.is_empty()
            || endpoints.len() > PeerDirectory::MAX_PEERS
            || endpoints.iter().any(|endpoint| endpoint.public_key.len() != 1312)
        {
            return Err(PeerConnectorError::InvalidConfiguration);
        }
        Ok(Self {
            endpoints,
            attempts: 3,
            connect_timeout: Duration::from_millis(500),
            backoff: Duration::from_millis(25),
        })
    }
    pub fn with_retry_policy(
        mut self,
        attempts: usize,
        connect_timeout: Duration,
        backoff: Duration,
    ) -> Result<Self, PeerConnectorError> {
        if attempts == 0 || attempts > 16 {
            return Err(PeerConnectorError::InvalidConfiguration);
        }
        self.attempts = attempts;
        self.connect_timeout = connect_timeout;
        self.backoff = backoff;
        Ok(self)
    }
    pub fn connect_all_authenticated(
        &self,
        local_peer_id: u16,
        signer: &ValidatorSigner,
        service: &ValidatorService,
    ) -> (PeerDirectory, Vec<(u16, std::io::Error)>) {
        let mut directory = PeerDirectory::new(
            Arc::clone(&service.session_store),
            service.session_store_path.clone(),
        );
        let mut failures = Vec::new();
        for endpoint in &self.endpoints {
            match self.connect_authenticated(endpoint, local_peer_id, signer, service) {
                Ok((socket, session)) => {
                    if let Err(error) =
                        directory.insert(endpoint.id, socket, endpoint.public_key.clone(), session)
                    {
                        failures.push((
                            endpoint.id,
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("peer registration failed: {error:?}"),
                            ),
                        ));
                    }
                }
                Err(error) => failures.push((endpoint.id, error)),
            }
        }
        (directory, failures)
    }
    pub fn reconnect(&self, endpoint: &PeerEndpoint) -> Result<PeerSocket, std::io::Error> {
        let mut last_error = None;
        for attempt in 0..self.attempts {
            match TcpStream::connect_timeout(&endpoint.address, self.connect_timeout) {
                Ok(stream) => return Ok(PeerSocket::connect(stream)),
                Err(error) => last_error = Some(error),
            }
            if attempt + 1 < self.attempts {
                std::thread::sleep(self.backoff.saturating_mul((attempt + 1) as u32));
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "reconnect failed")
        }))
    }
    pub fn connect_authenticated(
        &self,
        endpoint: &PeerEndpoint,
        local_peer_id: u16,
        signer: &ValidatorSigner,
        service: &ValidatorService,
    ) -> Result<(PeerSocket, PqPeerSession), std::io::Error> {
        let result = (|| {
            if service
                .sender_for(signer)
                .map_err(|_| invalid_data("unknown local session signer"))?
                != local_peer_id
            {
                return Err(invalid_data("local session signer identity mismatch"));
            }
            let mut socket = self.reconnect(endpoint)?;
            socket.set_timeouts(Some(PEER_FRAME_DEADLINE), Some(PEER_FRAME_DEADLINE))?;
            socket.set_absolute_deadline(Some(Instant::now() + PEER_FRAME_DEADLINE));
            let context = service.session_context(local_peer_id, endpoint.id)?;
            let session = socket.initiate_pq_session(context, signer, &endpoint.public_key)?;
            service.accept_session(&session)?;
            socket.set_absolute_deadline(Some(Instant::now() + PEER_SESSION_LIFETIME));
            socket.set_timeouts(Some(PEER_SESSION_IDLE_TIMEOUT), Some(PEER_FRAME_DEADLINE))?;
            Ok((socket, session))
        })();
        match result {
            Ok(connection) => {
                service.record_peer_session_established();
                Ok(connection)
            }
            Err(error) => {
                service.record_peer_session_rejection();
                service.record_peer_io_error(&error);
                Err(error)
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerConnectorError {
    InvalidConfiguration,
}
#[derive(Debug)]
pub enum PeerReceiveError {
    UnknownPeer,
    Io(std::io::Error),
    Transport(TransportError),
}

#[derive(Clone, Debug)]
pub struct PeerEvent {
    pub peer_id: u16,
    pub envelope: SignedPeerEnvelope,
}
pub struct PeerEventQueue {
    sender: SyncSender<PeerEvent>,
    receiver: Receiver<PeerEvent>,
}
impl Default for PeerEventQueue {
    fn default() -> Self {
        Self::new()
    }
}
impl PeerEventQueue {
    pub const DEFAULT_CAPACITY: usize = 1024;
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        Self { sender, receiver }
    }
    pub fn sender(&self) -> SyncSender<PeerEvent> {
        self.sender.clone()
    }
    pub fn push(&self, event: PeerEvent) -> Result<(), mpsc::SendError<PeerEvent>> {
        self.sender.send(event)
    }
    pub fn recv(&self) -> Result<PeerEvent, mpsc::RecvError> {
        self.receiver.recv()
    }
    pub fn try_recv(&self) -> Result<PeerEvent, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }
}

pub struct ConsensusDispatcher;
impl ConsensusDispatcher {
    pub fn dispatch_once<F>(queue: &PeerEventQueue, handler: F) -> Result<(), DispatchError>
    where
        F: FnOnce(PeerEvent) -> Result<(), String>,
    {
        let event = queue.recv().map_err(|_| DispatchError::QueueClosed)?;
        handler(event).map_err(DispatchError::Handler)
    }
}
#[derive(Debug, Eq, PartialEq)]
pub enum DispatchError {
    QueueClosed,
    Handler(String),
}

pub struct PeerSupervisor {
    handles: Vec<std::thread::JoinHandle<()>>,
}
impl Default for PeerSupervisor {
    fn default() -> Self {
        Self::new()
    }
}
impl PeerSupervisor {
    pub fn new() -> Self {
        Self { handles: Vec::new() }
    }
    pub fn spawn<F>(&mut self, worker: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.handles.push(std::thread::spawn(worker));
    }
    pub fn join_all(self) -> std::thread::Result<()> {
        for handle in self.handles {
            handle.join()?;
        }
        Ok(())
    }
}

pub fn save_snapshot(path: &std::path::Path, state: &ConsensusState) -> std::io::Result<()> {
    let bytes = match std::fs::read(path) {
        Ok(existing) => match decode_validator_snapshot(&existing) {
            Ok((mut persisted, _)) => {
                persisted.consensus = state.snapshot();
                encode_envelope(&persisted).map_err(|_| invalid_data("snapshot encoding failed"))?
            }
            Err(_) if existing.starts_with(&PersistedValidatorState::TYPE_TAG.to_be_bytes()) => {
                return Err(invalid_data("validator safety snapshot is invalid"));
            }
            Err(_) => encode_envelope(&state.snapshot())
                .map_err(|_| invalid_data("snapshot encoding failed"))?,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            encode_envelope(&state.snapshot())
                .map_err(|_| invalid_data("snapshot encoding failed"))?
        }
        Err(error) => return Err(error),
    };
    write_atomic(path, &bytes)
}
pub fn load_snapshot(path: &std::path::Path) -> std::io::Result<ConsensusState> {
    let bytes = std::fs::read(path)?;
    if let Ok((snapshot, _)) = decode_validator_snapshot(&bytes) {
        return Ok(ConsensusState::from_snapshot(snapshot.consensus));
    }
    let snapshot: ConsensusSnapshot = decode_envelope(&bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "snapshot decoding failed")
    })?;
    Ok(ConsensusState::from_snapshot(snapshot))
}

/// Returns the immutable chain genesis commitment retained by a validator safety snapshot.
/// Raw consensus-only snapshots predate this binding and return `None`.
pub fn load_snapshot_chain_genesis_commitment(
    path: &std::path::Path,
) -> std::io::Result<Option<Digest384>> {
    let bytes = std::fs::read(path)?;
    match decode_validator_snapshot(&bytes) {
        Ok((snapshot, _)) => Ok(Some(snapshot.genesis_commitment)),
        Err(_) if bytes.starts_with(&PersistedValidatorState::TYPE_TAG.to_be_bytes()) => {
            Err(invalid_data("validator safety snapshot is invalid"))
        }
        Err(_) => Ok(None),
    }
}

/// Decodes schema 6 directly and performs bounded schema-5/schema-4 migrations by appending the
/// absent optional view-change proof. Schema 4 remains migratable only when its old reduced
/// certified-history representation was empty; non-empty QC-only history still fails closed.
fn decode_validator_snapshot(bytes: &[u8]) -> Result<(PersistedValidatorState, bool), DecodeError> {
    if let Ok(snapshot) = decode_envelope::<PersistedValidatorState>(bytes) {
        return Ok((snapshot, false));
    }
    if bytes.len() < 4 || bytes[..2] != PersistedValidatorState::TYPE_TAG.to_be_bytes() {
        return Err(DecodeError::InvalidValue("unsupported validator safety snapshot"));
    }
    let old_schema = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
    if old_schema != 4 && old_schema != 5 {
        return Err(DecodeError::InvalidValue("unsupported validator safety snapshot"));
    }
    let migrated = append_validator_snapshot_body_suffix(
        bytes,
        PersistedValidatorState::SCHEMA_VERSION,
        &[0, 0], // Option::None plus an empty timeout-lock set
    )?;
    decode_envelope::<PersistedValidatorState>(&migrated)
        .map(|snapshot| (snapshot, true))
        .map_err(|_| DecodeError::InvalidValue("legacy snapshot cannot be migrated safely"))
}

fn append_validator_snapshot_body_suffix(
    bytes: &[u8],
    schema_version: u16,
    suffix: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    const CANONICAL_MAX_LENGTH_PREFIX: usize = 5;
    let mut prefix_end = 4_usize;
    let mut body_length = 0_u32;
    for index in 0..CANONICAL_MAX_LENGTH_PREFIX {
        let byte = *bytes
            .get(prefix_end)
            .ok_or(DecodeError::InvalidValue("legacy snapshot length prefix is truncated"))?;
        prefix_end += 1;
        if index == CANONICAL_MAX_LENGTH_PREFIX - 1 && byte > 0x0f {
            return Err(DecodeError::LengthOverflow);
        }
        body_length |= u32::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if activechain_canonical_codec::canonical_length_prefix_len(body_length) != index + 1 {
                return Err(DecodeError::NonMinimalLength);
            }
            break;
        }
        if index == CANONICAL_MAX_LENGTH_PREFIX - 1 {
            return Err(DecodeError::LengthOverflow);
        }
    }
    let body_length = body_length as usize;
    if prefix_end.checked_add(body_length) != Some(bytes.len()) {
        return Err(DecodeError::InvalidValue("legacy snapshot envelope length is inconsistent"));
    }
    let new_length = body_length.checked_add(suffix.len()).ok_or(DecodeError::LengthOverflow)?;
    if new_length > PersistedValidatorState::MAX_ENCODED_LEN {
        return Err(DecodeError::LengthLimitExceeded {
            length: new_length,
            maximum: PersistedValidatorState::MAX_ENCODED_LEN,
        });
    }
    let mut migrated = Vec::with_capacity(bytes.len() + suffix.len() + 1);
    migrated.extend_from_slice(&bytes[..2]);
    migrated.extend_from_slice(&schema_version.to_be_bytes());
    let mut remaining = u32::try_from(new_length).map_err(|_| DecodeError::LengthOverflow)?;
    loop {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        migrated.push(byte);
        if remaining == 0 {
            break;
        }
    }
    migrated.extend_from_slice(&bytes[prefix_end..]);
    migrated.extend_from_slice(suffix);
    Ok(migrated)
}

fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let file_name =
        path.file_name().ok_or_else(|| invalid_data("atomic persistence path has no file name"))?;
    let mut temporary_name = file_name.to_os_string();
    temporary_name.push(".tmp");
    let temporary = path.with_file_name(temporary_name);
    let mut file = std::fs::File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn save_validator_snapshot(
    path: &std::path::Path,
    engine: &ValidatorEngine,
    replay: &ReplayGuard,
    outbound_high_water: &BTreeMap<u16, u64>,
) -> std::io::Result<()> {
    let snapshot = PersistedValidatorState {
        consensus: engine.state.snapshot(),
        genesis_commitment: engine.genesis_commitment,
        replay_high_water: replay.highest.clone(),
        outbound_high_water: outbound_high_water.clone(),
        vote_locks: engine.local_vote_locks.clone(),
        highest_voted_rounds: engine.highest_voted_rounds.clone(),
        locked_qc: engine.locked_qc.clone(),
        certified_blocks: engine.certified_blocks.clone(),
        active_anchor: engine.active_anchor,
        accepted_view_change: engine.accepted_view_change.clone(),
        timeout_locks: engine.timeout_locks.clone(),
    };
    let bytes = encode_envelope(&snapshot).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("validator safety snapshot encoding failed: {error:?}"),
        )
    })?;
    write_atomic(path, &bytes)
}
pub fn load_genesis(path: &std::path::Path) -> std::io::Result<ValidatorGenesis> {
    let bytes = std::fs::read(path)?;
    decode_envelope(&bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "genesis encoding invalid")
    })
}
pub fn open_protected_payload<T: activechain_canonical_codec::CanonicalType>(
    encoded_envelope: &[u8],
    recipient: &activechain_crypto_provider::MlKem768Recipient,
    associated_data: &[u8],
) -> std::io::Result<T> {
    let protected = activechain_crypto_provider::ProtectedEnvelope::decode(encoded_envelope)
        .map_err(|_| invalid_data("protected envelope is invalid"))?;
    let plaintext = protected
        .open(recipient, associated_data)
        .map_err(|_| invalid_data("protected envelope authentication failed"))?;
    decode_envelope(&plaintext).map_err(|_| invalid_data("protected payload is not canonical"))
}
pub fn verify_execution_evidence(
    evidence: &activechain_object_vm::ExecutionEvidence,
) -> Result<(), RuntimeAdmissionError> {
    evidence.verify().map_err(|_| RuntimeAdmissionError::ExecutionEvidenceInvalid)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAdmissionError {
    ExecutionEvidenceInvalid,
}
pub fn save_distributed_snapshot(
    path: &std::path::Path,
    state: &ConsensusState,
    data_shards: usize,
    parity_shards: usize,
) -> std::io::Result<()> {
    let state_bytes =
        encode_envelope(&state.snapshot()).map_err(|_| invalid_data("snapshot encoding failed"))?;
    let batch = activechain_data_availability::AvailabilityBatch::encode(
        &state_bytes,
        data_shards,
        parity_shards,
    )
    .map_err(|_| invalid_data("snapshot shard encoding failed"))?
    .serialize()
    .map_err(|_| invalid_data("snapshot shard serialization failed"))?;
    let mut bytes = Vec::with_capacity(13 + state_bytes.len() + batch.len());
    bytes.extend_from_slice(b"ACSN1");
    bytes.extend_from_slice(&(state_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(batch.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&state_bytes);
    bytes.extend_from_slice(&batch);
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, path)
}
pub fn load_distributed_snapshot(path: &std::path::Path) -> std::io::Result<ConsensusState> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < 13 || &bytes[..5] != b"ACSN1" {
        return Err(invalid_data("invalid distributed snapshot"));
    }
    let state_len = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    let batch_len = u32::from_be_bytes(bytes[9..13].try_into().unwrap()) as usize;
    if bytes.len() != 13 + state_len + batch_len {
        return Err(invalid_data("distributed snapshot length mismatch"));
    }
    let state_bytes = &bytes[13..13 + state_len];
    let batch_bytes = &bytes[13 + state_len..];
    let batch = activechain_data_availability::AvailabilityBatch::deserialize(batch_bytes)
        .map_err(|_| invalid_data("distributed snapshot shards invalid"))?;
    let reconstructed = batch
        .reconstruct_payload(&[])
        .map_err(|_| invalid_data("distributed snapshot reconstruction failed"))?;
    if reconstructed != state_bytes {
        return Err(invalid_data("distributed snapshot state mismatch"));
    }
    let snapshot: ConsensusSnapshot = decode_envelope(&reconstructed)
        .map_err(|_| invalid_data("distributed snapshot decoding failed"))?;
    Ok(ConsensusState::from_snapshot(snapshot))
}
impl PeerSocket {
    pub fn connect(stream: TcpStream) -> Self {
        Self { stream, absolute_deadline: None, session_messages: 0 }
    }
    pub fn set_timeouts(
        &self,
        read: Option<std::time::Duration>,
        write: Option<std::time::Duration>,
    ) -> std::io::Result<()> {
        self.stream.set_read_timeout(read)?;
        self.stream.set_write_timeout(write)
    }
    pub fn set_absolute_deadline(&mut self, deadline: Option<Instant>) {
        self.absolute_deadline = deadline;
    }
    pub(crate) fn ensure_session_message_capacity(&self) -> std::io::Result<()> {
        if self.session_messages >= MAX_PEER_SESSION_MESSAGES {
            return Err(invalid_data("authenticated peer session message limit reached"));
        }
        Ok(())
    }
    pub(crate) fn record_session_message(&mut self) {
        self.session_messages += 1;
    }
    fn operation_deadline(&self) -> Instant {
        let frame_deadline = Instant::now() + PEER_FRAME_DEADLINE;
        self.absolute_deadline.map_or(frame_deadline, |cap| cap.min(frame_deadline))
    }
    fn remaining(deadline: Instant) -> std::io::Result<Duration> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "peer frame deadline exceeded")
            })
    }
    fn read_exact_until(&mut self, bytes: &mut [u8], deadline: Instant) -> std::io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.stream.set_read_timeout(Some(Self::remaining(deadline)?))?;
            match self.stream.read(&mut bytes[offset..]) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer closed during frame",
                    ));
                }
                Ok(read) => offset += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn write_all_until(&mut self, bytes: &[u8], deadline: Instant) -> std::io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.stream.set_write_timeout(Some(Self::remaining(deadline)?))?;
            match self.stream.write(&bytes[offset..]) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "peer stopped accepting frame",
                    ));
                }
                Ok(written) => offset += written,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    pub(crate) fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        if frame.len() > MAX_PEER_FRAME_LEN {
            return Err(invalid_data("peer frame exceeds limit"));
        }
        let deadline = self.operation_deadline();
        self.write_all_until(&(frame.len() as u32).to_be_bytes(), deadline)?;
        self.write_all_until(frame, deadline)
    }
    #[cfg(test)]
    pub fn send(&mut self, envelope: &SignedPeerEnvelope) -> std::io::Result<()> {
        let mut frame = Vec::with_capacity(2 + 8 + 48 + 2 + envelope.signature_bytes().len());
        frame.extend_from_slice(&envelope.sender().to_be_bytes());
        frame.extend_from_slice(&envelope.sequence().to_be_bytes());
        frame.extend_from_slice(envelope.body_digest().as_bytes());
        frame.extend_from_slice(&(envelope.signature_bytes().len() as u16).to_be_bytes());
        frame.extend_from_slice(envelope.signature_bytes());
        self.write_frame(&frame)
    }
    pub fn receive_frame(&mut self) -> std::io::Result<Vec<u8>> {
        let idle_deadline = Instant::now() + PEER_SESSION_IDLE_TIMEOUT;
        let idle_deadline =
            self.absolute_deadline.map_or(idle_deadline, |cap| cap.min(idle_deadline));
        let mut len = [0; 4];
        self.read_exact_until(&mut len[..1], idle_deadline)?;
        let frame_deadline = self.operation_deadline();
        self.read_exact_until(&mut len[1..], frame_deadline)?;
        self.receive_frame_body(len, frame_deadline)
    }
    #[cfg(test)]
    fn receive_frame_until(&mut self, deadline: Instant) -> std::io::Result<Vec<u8>> {
        let mut len = [0; 4];
        self.read_exact_until(&mut len, deadline)?;
        self.receive_frame_body(len, deadline)
    }
    fn receive_frame_body(&mut self, len: [u8; 4], deadline: Instant) -> std::io::Result<Vec<u8>> {
        let frame_len = u32::from_be_bytes(len) as usize;
        if frame_len > MAX_PEER_FRAME_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer frame exceeds limit",
            ));
        }
        let mut frame = vec![0; frame_len];
        self.read_exact_until(&mut frame, deadline)?;
        Ok(frame)
    }
    #[cfg(test)]
    pub fn receive_envelope(&mut self) -> std::io::Result<SignedPeerEnvelope> {
        let frame = self.receive_frame()?;
        if frame.len() < 2 + 8 + 48 + 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer frame too short",
            ));
        }
        let sender = u16::from_be_bytes([frame[0], frame[1]]);
        let sequence = u64::from_be_bytes(frame[2..10].try_into().unwrap());
        let body_digest = Digest384::new(frame[10..58].try_into().unwrap());
        let signature_len = u16::from_be_bytes([frame[58], frame[59]]) as usize;
        if frame.len() != 60 + signature_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer signature length mismatch",
            ));
        }
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, frame[60..].to_vec())
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid ML-DSA signature")
            })?;
        SignedPeerEnvelope::new(sender, sequence, body_digest, signature).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid peer envelope")
        })
    }
    #[cfg(test)]
    pub fn send_message(
        &mut self,
        authenticated: &AuthenticatedConsensusMessage,
    ) -> std::io::Result<()> {
        let frame = authenticated.wire_bytes()?;
        self.write_frame(&frame)
    }
    #[cfg(test)]
    pub fn receive_message(&mut self) -> std::io::Result<AuthenticatedConsensusMessage> {
        let frame = self.receive_frame()?;
        AuthenticatedConsensusMessage::from_wire_bytes(&frame)
    }
}
fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}
fn transport_io_error(error: TransportError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{error:?}"))
}
#[derive(Debug, Eq, PartialEq)]
pub enum TransportError {
    InvalidSuite,
    InvalidMessageKind,
    InvalidBody,
    BodyDigestMismatch,
    Verification(VerificationError),
    Replay,
    SenderMismatch,
    RateLimited,
}

#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ReplayGuard {
    highest: BTreeMap<u16, u64>,
}
impl ReplayGuard {
    pub fn accept(
        &mut self,
        envelope: &SignedPeerEnvelope,
        public_key: &[u8],
    ) -> Result<(), TransportError> {
        envelope.verify(public_key)?;
        if self
            .highest
            .get(&envelope.sender())
            .is_some_and(|highest| envelope.sequence() <= *highest)
        {
            return Err(TransportError::Replay);
        }
        self.highest.insert(envelope.sender(), envelope.sequence());
        Ok(())
    }
}

const MAX_PERSISTED_REPLAY_SENDERS: usize = activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH;
const MAX_PERSISTED_VOTE_LOCKS: usize = 4096;
const MAX_PERSISTED_CERTIFIED_BLOCKS: usize = 4096;
const MAX_ACTIVE_COLLECTORS: usize = activechain_protocol_types::MAX_VALIDATORS_PER_EPOCH;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TimeoutSlot {
    height: u64,
    round: u64,
    parent: ConsensusBlockRef,
    highest_qc: Digest384,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TimeoutCollectorKey {
    height: u64,
    round: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LocalTimeoutDomain {
    validator: PrincipalId,
    genesis_commitment: Digest384,
    epoch: u64,
    validator_set_root: Digest384,
    protocol_revision: u64,
    height: u64,
    round: u64,
}

#[derive(Clone)]
struct TimeoutCollector {
    context: ConsensusVoteContext,
    key: TimeoutCollectorKey,
    votes: BTreeMap<PrincipalId, TimeoutVote>,
    signer_stake: u128,
}

impl TimeoutCollector {
    fn from_vote(vote: &TimeoutVote) -> Self {
        Self {
            context: vote.context(),
            key: TimeoutCollectorKey { height: vote.height(), round: vote.timed_out_round() },
            votes: BTreeMap::new(),
            signer_stake: 0,
        }
    }
    fn add(
        &mut self,
        vote: TimeoutVote,
        validator_set: &ValidatorSet,
        public_key: &[u8],
    ) -> Result<(), ValidatorEngineError> {
        if vote.context() != self.context
            || vote.height() != self.key.height
            || vote.timed_out_round() != self.key.round
        {
            return Err(ValidatorEngineError::InvalidViewChange);
        }
        if self.votes.contains_key(&vote.validator()) {
            return Err(ValidatorEngineError::DuplicateTimeoutVote);
        }
        verify_ml_dsa44(public_key, &vote.signing_payload(), vote.signature().as_bytes())
            .map_err(|_| ValidatorEngineError::InvalidViewChange)?;
        let stake = validator_set
            .stake_of(&vote.validator())
            .ok_or(ValidatorEngineError::UnknownValidator)?;
        self.signer_stake =
            self.signer_stake.checked_add(stake).ok_or(ValidatorEngineError::InvalidViewChange)?;
        self.votes.insert(vote.validator(), vote);
        Ok(())
    }
    fn certificate(
        &self,
        validator_set: &ValidatorSet,
    ) -> Result<Option<ViewChangeCertificate>, ValidatorEngineError> {
        let has_quorum = self
            .signer_stake
            .checked_mul(3)
            .zip(validator_set.total_stake().checked_mul(2))
            .is_some_and(|(signed, total)| signed > total);
        if !has_quorum {
            return Ok(None);
        }
        let selected = self
            .votes
            .values()
            .filter_map(|vote| vote.highest_qc().map(|qc| (qc, vote.parent())))
            .max_by_key(|(qc, _)| (qc.round(), qc.height(), qc.proposal_commitment()));
        let (highest_qc, parent) = selected.map_or_else(
            || (None, self.votes.values().next().unwrap().parent()),
            |(qc, parent)| (Some(qc.clone()), parent),
        );
        ViewChangeCertificate::new(
            self.context,
            self.key.height,
            self.key.round,
            parent,
            highest_qc,
            validator_set.total_stake(),
            self.signer_stake,
            self.votes.values().cloned().collect(),
        )
        .map(Some)
        .map_err(|_| ValidatorEngineError::InvalidViewChange)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LocalVoteSlot {
    validator: PrincipalId,
    genesis_commitment: Digest384,
    epoch: u64,
    validator_set_root: Digest384,
    protocol_revision: u64,
    height: u64,
    round: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LocalVoteDomain {
    validator: PrincipalId,
    genesis_commitment: Digest384,
    epoch: u64,
    validator_set_root: Digest384,
    protocol_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HighestVotedRound {
    height: u64,
    round: u64,
    proposal_commitment: Digest384,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CertifiedBlockRecord {
    proposal: BlockProposal,
    certificate: QuorumCertificate,
    votes: Vec<ValidatorVote>,
    parent: ConsensusBlockRef,
}

impl CertifiedBlockRecord {
    fn from_verified(proof: &CertifiedBlock) -> Self {
        Self {
            proposal: proof.proposal().clone(),
            certificate: proof.certificate().clone(),
            votes: proof.votes().to_vec(),
            parent: proof.proposal().parent(),
        }
    }

    fn proof(&self) -> Result<CertifiedBlock, TransportError> {
        CertifiedBlock::new(self.proposal.clone(), self.certificate.clone(), self.votes.clone())
    }
}

impl CanonicalEncode for CertifiedBlockRecord {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        let proof = self.proof().map_err(|_| EncodeError::LengthOverflow)?;
        let bytes = proof.encode().map_err(|_| EncodeError::LengthOverflow)?;
        encoder.write_bytes(&bytes, MAX_PEER_FRAME_LEN)
    }
}

impl CanonicalDecode for CertifiedBlockRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let proof = CertifiedBlock::decode(decoder.read_bytes(MAX_PEER_FRAME_LEN)?)
            .map_err(|_| DecodeError::InvalidValue("invalid certified-block proof"))?;
        Ok(Self::from_verified(&proof))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersistedValidatorState {
    consensus: ConsensusSnapshot,
    genesis_commitment: Digest384,
    replay_high_water: BTreeMap<u16, u64>,
    outbound_high_water: BTreeMap<u16, u64>,
    vote_locks: BTreeMap<LocalVoteSlot, Digest384>,
    highest_voted_rounds: BTreeMap<LocalVoteDomain, HighestVotedRound>,
    locked_qc: Option<QuorumCertificate>,
    certified_blocks: BTreeMap<Digest384, CertifiedBlockRecord>,
    active_anchor: ConsensusBlockRef,
    accepted_view_change: Option<ViewChangeCertificate>,
    timeout_locks: BTreeMap<LocalTimeoutDomain, TimeoutSlot>,
}

/// Stable marker used by deployment preflight before a validator binary is promoted.
pub const PERSISTED_VALIDATOR_STATE_TYPE_TAG: u16 = PersistedValidatorState::TYPE_TAG;
pub const PERSISTED_VALIDATOR_STATE_SCHEMA_VERSION: u16 = PersistedValidatorState::SCHEMA_VERSION;

impl CanonicalEncode for PersistedValidatorState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.consensus.encode(encoder)?;
        self.genesis_commitment.encode(encoder)?;
        encoder.write_length(self.replay_high_water.len(), MAX_PERSISTED_REPLAY_SENDERS)?;
        for (sender, sequence) in &self.replay_high_water {
            sender.encode(encoder)?;
            sequence.encode(encoder)?;
        }
        encoder.write_length(self.outbound_high_water.len(), MAX_PERSISTED_REPLAY_SENDERS)?;
        for (sender, sequence) in &self.outbound_high_water {
            sender.encode(encoder)?;
            sequence.encode(encoder)?;
        }
        encoder.write_length(self.vote_locks.len(), MAX_PERSISTED_VOTE_LOCKS)?;
        for (slot, digest) in &self.vote_locks {
            slot.validator.encode(encoder)?;
            slot.genesis_commitment.encode(encoder)?;
            slot.epoch.encode(encoder)?;
            slot.validator_set_root.encode(encoder)?;
            slot.protocol_revision.encode(encoder)?;
            slot.height.encode(encoder)?;
            slot.round.encode(encoder)?;
            digest.encode(encoder)?;
        }
        encoder.write_length(self.highest_voted_rounds.len(), MAX_PERSISTED_REPLAY_SENDERS)?;
        for (domain, highest) in &self.highest_voted_rounds {
            domain.validator.encode(encoder)?;
            domain.genesis_commitment.encode(encoder)?;
            domain.epoch.encode(encoder)?;
            domain.validator_set_root.encode(encoder)?;
            domain.protocol_revision.encode(encoder)?;
            highest.height.encode(encoder)?;
            highest.round.encode(encoder)?;
            highest.proposal_commitment.encode(encoder)?;
        }
        self.locked_qc.encode(encoder)?;
        encoder.write_length(self.certified_blocks.len(), MAX_PERSISTED_CERTIFIED_BLOCKS)?;
        for (digest, record) in &self.certified_blocks {
            digest.encode(encoder)?;
            record.encode(encoder)?;
        }
        self.active_anchor.encode(encoder)?;
        self.accepted_view_change.encode(encoder)?;
        encoder.write_length(self.timeout_locks.len(), MAX_PERSISTED_VOTE_LOCKS)?;
        for (domain, slot) in &self.timeout_locks {
            domain.validator.encode(encoder)?;
            domain.genesis_commitment.encode(encoder)?;
            domain.epoch.encode(encoder)?;
            domain.validator_set_root.encode(encoder)?;
            domain.protocol_revision.encode(encoder)?;
            domain.height.encode(encoder)?;
            domain.round.encode(encoder)?;
            slot.height.encode(encoder)?;
            slot.round.encode(encoder)?;
            slot.parent.encode(encoder)?;
            slot.highest_qc.encode(encoder)?;
        }
        Ok(())
    }
}

impl CanonicalDecode for PersistedValidatorState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let consensus = ConsensusSnapshot::decode(decoder)?;
        let genesis_commitment = Digest384::decode(decoder)?;
        if genesis_commitment == Digest384::ZERO {
            return Err(DecodeError::InvalidValue("zero consensus genesis commitment"));
        }
        let replay_count = decoder.read_length(MAX_PERSISTED_REPLAY_SENDERS)?;
        let mut replay_high_water = BTreeMap::new();
        let mut previous_sender = None;
        for _ in 0..replay_count {
            let sender = u16::decode(decoder)?;
            let sequence = u64::decode(decoder)?;
            if sender == 0
                || previous_sender.is_some_and(|previous| sender <= previous)
                || replay_high_water.insert(sender, sequence).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid replay high-water entry"));
            }
            previous_sender = Some(sender);
        }
        let outbound_count = decoder.read_length(MAX_PERSISTED_REPLAY_SENDERS)?;
        let mut outbound_high_water = BTreeMap::new();
        let mut previous_sender = None;
        for _ in 0..outbound_count {
            let sender = u16::decode(decoder)?;
            let sequence = u64::decode(decoder)?;
            if sender == 0
                || previous_sender.is_some_and(|previous| sender <= previous)
                || outbound_high_water.insert(sender, sequence).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid outbound high-water entry"));
            }
            previous_sender = Some(sender);
        }
        let vote_count = decoder.read_length(MAX_PERSISTED_VOTE_LOCKS)?;
        let mut vote_locks = BTreeMap::new();
        let mut previous_slot = None;
        for _ in 0..vote_count {
            let slot = LocalVoteSlot {
                validator: PrincipalId::decode(decoder)?,
                genesis_commitment: Digest384::decode(decoder)?,
                epoch: u64::decode(decoder)?,
                validator_set_root: Digest384::decode(decoder)?,
                protocol_revision: u64::decode(decoder)?,
                height: u64::decode(decoder)?,
                round: u64::decode(decoder)?,
            };
            let digest = Digest384::decode(decoder)?;
            if slot.genesis_commitment == Digest384::ZERO
                || slot.validator_set_root == Digest384::ZERO
                || slot.protocol_revision == 0
                || digest == Digest384::ZERO
                || previous_slot.is_some_and(|previous| slot <= previous)
                || vote_locks.insert(slot, digest).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid local vote lock"));
            }
            previous_slot = Some(slot);
        }
        let highest_count = decoder.read_length(MAX_PERSISTED_REPLAY_SENDERS)?;
        let mut highest_voted_rounds = BTreeMap::new();
        let mut previous_domain = None;
        for _ in 0..highest_count {
            let domain = LocalVoteDomain {
                validator: PrincipalId::decode(decoder)?,
                genesis_commitment: Digest384::decode(decoder)?,
                epoch: u64::decode(decoder)?,
                validator_set_root: Digest384::decode(decoder)?,
                protocol_revision: u64::decode(decoder)?,
            };
            let highest = HighestVotedRound {
                height: u64::decode(decoder)?,
                round: u64::decode(decoder)?,
                proposal_commitment: Digest384::decode(decoder)?,
            };
            if domain.genesis_commitment == Digest384::ZERO
                || domain.validator_set_root == Digest384::ZERO
                || domain.protocol_revision == 0
                || highest.proposal_commitment == Digest384::ZERO
                || previous_domain.is_some_and(|previous| domain <= previous)
                || highest_voted_rounds.insert(domain, highest).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid durable highest-voted round"));
            }
            previous_domain = Some(domain);
        }
        let locked_qc = Option::<QuorumCertificate>::decode(decoder)?;
        let certified_count = decoder.read_length(MAX_PERSISTED_CERTIFIED_BLOCKS)?;
        let mut certified_blocks = BTreeMap::new();
        let mut previous_digest = None;
        for _ in 0..certified_count {
            let digest = Digest384::decode(decoder)?;
            let record = CertifiedBlockRecord::decode(decoder)?;
            if digest == Digest384::ZERO
                || digest != record.certificate.proposal_commitment()
                || previous_digest.is_some_and(|previous| digest <= previous)
                || certified_blocks.insert(digest, record).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid certified-block record"));
            }
            previous_digest = Some(digest);
        }
        let active_anchor = ConsensusBlockRef::decode(decoder)?;
        let accepted_view_change = Option::<ViewChangeCertificate>::decode(decoder)?;
        let timeout_lock_count = decoder.read_length(MAX_PERSISTED_VOTE_LOCKS)?;
        let mut timeout_locks = BTreeMap::new();
        let mut previous_timeout_domain = None;
        for _ in 0..timeout_lock_count {
            let domain = LocalTimeoutDomain {
                validator: PrincipalId::decode(decoder)?,
                genesis_commitment: Digest384::decode(decoder)?,
                epoch: u64::decode(decoder)?,
                validator_set_root: Digest384::decode(decoder)?,
                protocol_revision: u64::decode(decoder)?,
                height: u64::decode(decoder)?,
                round: u64::decode(decoder)?,
            };
            let slot = TimeoutSlot {
                height: u64::decode(decoder)?,
                round: u64::decode(decoder)?,
                parent: ConsensusBlockRef::decode(decoder)?,
                highest_qc: Digest384::decode(decoder)?,
            };
            if domain.genesis_commitment == Digest384::ZERO
                || domain.validator_set_root == Digest384::ZERO
                || domain.protocol_revision == 0
                || domain.height != slot.height
                || domain.round != slot.round
                || previous_timeout_domain.is_some_and(|previous| domain <= previous)
                || timeout_locks.insert(domain, slot).is_some()
            {
                return Err(DecodeError::InvalidValue("invalid timeout-vote lock"));
            }
            previous_timeout_domain = Some(domain);
        }
        if locked_qc.as_ref().is_some_and(|locked| {
            let is_finalized_anchor = locked.block_digest() == active_anchor.block_digest()
                && locked.proposal_commitment() == active_anchor.proposal_commitment()
                && locked.height() == active_anchor.height()
                && locked.round() == active_anchor.round();
            !is_finalized_anchor
                && certified_blocks
                    .get(&locked.proposal_commitment())
                    .is_none_or(|record| record.certificate != *locked)
        }) {
            return Err(DecodeError::InvalidValue("locked QC is not durably certified"));
        }
        Ok(Self {
            consensus,
            genesis_commitment,
            replay_high_water,
            outbound_high_water,
            vote_locks,
            highest_voted_rounds,
            locked_qc,
            certified_blocks,
            active_anchor,
            accepted_view_change,
            timeout_locks,
        })
    }
}

impl CanonicalType for PersistedValidatorState {
    const TYPE_TAG: u16 = 0x006c;
    const SCHEMA_VERSION: u16 = 6;
    const MAX_ENCODED_LEN: usize = ConsensusSnapshot::MAX_ENCODED_LEN
        + 48
        + 2
        + MAX_PERSISTED_REPLAY_SENDERS * (2 + 8)
        + 2
        + MAX_PERSISTED_REPLAY_SENDERS * (2 + 8)
        + 2
        + MAX_PERSISTED_VOTE_LOCKS * (48 + 48 + 8 + 48 + 8 + 8 + 8 + 48)
        + 2
        + MAX_PERSISTED_REPLAY_SENDERS * (48 + 48 + 8 + 48 + 8 + 8 + 8 + 48)
        + 1
        + QuorumCertificate::ENCODED_LENGTH
        + 2
        + MAX_PERSISTED_CERTIFIED_BLOCKS * (48 + 5 + MAX_PEER_FRAME_LEN)
        + 48
        + 48
        + 8
        + 8
        + 1
        + ViewChangeCertificate::MAX_ENCODED_LEN
        + 2
        + MAX_PERSISTED_VOTE_LOCKS * (48 + 48 + 8 + 48 + 8 + 8 + 8 + 8 + 8 + 112 + 48);
}

/// Verifies the weighted PQ signatures and active context of a bare QC without changing state.
///
/// A successful return proves only that the QC is well formed. It does **not** establish finality;
/// the authoritative [`ValidatorEngine`] additionally requires its signed proposal ancestry and a
/// consecutive child QC before applying a committed parent.
pub fn verify_bare_qc_evidence(
    state: &ConsensusState,
    validator_set: &ValidatorSet,
    certificate: &QuorumCertificate,
    votes: &[(&[u8], ValidatorVote)],
) -> Result<(), RuntimeError> {
    if votes.iter().any(|(_, vote)| {
        vote.epoch() != state.epoch()
            || vote.validator_set_root() != state.validator_set_root()
            || vote.protocol_revision() != state.protocol_revision()
    }) {
        return Err(RuntimeError::State(ConsensusStateError::InvalidConsensusContext));
    }
    verify_quorum_certificate(certificate, validator_set, votes)
        .map_err(RuntimeError::VoteVerification)
}

#[derive(Debug, Eq, PartialEq)]
pub enum RuntimeError {
    VoteVerification(VerificationError),
    State(ConsensusStateError),
}

pub fn admit_proposal(
    state: &ConsensusState,
    genesis_commitment: Digest384,
    proposal: &BlockProposal,
    proposer_key: &[u8],
) -> Result<(), ProposalError> {
    verify_block_proposal(proposer_key, proposal).map_err(ProposalError::Verification)?;
    if proposal.genesis_commitment() != genesis_commitment
        || proposal.epoch() != state.epoch()
        || proposal.validator_set_root() != state.validator_set_root()
        || proposal.protocol_revision() != state.protocol_revision()
    {
        return Err(ProposalError::ConsensusContextMismatch);
    }
    if proposal.height() <= state.finalized_height() {
        return Err(ProposalError::StaleOrWrongEpoch);
    }
    Ok(())
}
#[derive(Debug, Eq, PartialEq)]
pub enum ProposalError {
    Verification(VerificationError),
    ConsensusContextMismatch,
    StaleOrWrongEpoch,
}

#[derive(Clone)]
pub struct VoteCollector {
    proposal: BlockProposal,
    genesis_commitment: Digest384,
    validator_set_root: Digest384,
    protocol_revision: u64,
    votes: Vec<(Vec<u8>, ValidatorVote)>,
    seen: BTreeMap<activechain_protocol_types::PrincipalId, ()>,
    signer_stake: u128,
}
impl VoteCollector {
    pub fn new(
        proposal: BlockProposal,
        genesis_commitment: Digest384,
        validator_set_root: Digest384,
        protocol_revision: u64,
    ) -> Self {
        Self {
            proposal,
            genesis_commitment,
            validator_set_root,
            protocol_revision,
            votes: Vec::new(),
            seen: BTreeMap::new(),
            signer_stake: 0,
        }
    }
    pub fn add_vote(
        &mut self,
        validator_set: &ValidatorSet,
        public_key: &[u8],
        vote: ValidatorVote,
    ) -> Result<(), VoteCollectionError> {
        if vote.genesis_commitment() != self.genesis_commitment
            || vote.epoch() != self.proposal.epoch()
            || vote.validator_set_root() != self.validator_set_root
            || vote.protocol_revision() != self.protocol_revision
            || vote.height() != self.proposal.height()
            || vote.round() != self.proposal.round()
            || vote.block_digest() != self.proposal.block_digest()
            || vote.proposal_commitment() != self.proposal.commitment()
        {
            return Err(VoteCollectionError::ContextMismatch);
        }
        if self.seen.contains_key(&vote.validator()) {
            return Err(VoteCollectionError::Duplicate);
        }
        let stake = validator_set
            .stake_of(&vote.validator())
            .ok_or(VoteCollectionError::UnknownValidator)?;
        activechain_crypto_provider::verify_validator_vote(public_key, &vote)
            .map_err(VoteCollectionError::Verification)?;
        let insert_at = self
            .votes
            .binary_search_by_key(&vote.validator(), |(_, existing)| existing.validator())
            .unwrap_err();
        self.seen.insert(vote.validator(), ());
        self.signer_stake =
            self.signer_stake.checked_add(stake).ok_or(VoteCollectionError::StakeOverflow)?;
        self.votes.insert(insert_at, (public_key.to_vec(), vote));
        Ok(())
    }
    pub fn signer_stake(&self) -> u128 {
        self.signer_stake
    }
    pub const fn proposal(&self) -> &BlockProposal {
        &self.proposal
    }
    pub fn votes(&self) -> &[(Vec<u8>, ValidatorVote)] {
        &self.votes
    }
    pub fn finalize(
        &self,
        epoch: u64,
        validator_set: &ValidatorSet,
    ) -> Result<QuorumCertificate, VoteCollectionError> {
        if epoch != self.proposal.epoch() {
            return Err(VoteCollectionError::ContextMismatch);
        }
        let total = validator_set.total_stake();
        if self.signer_stake.checked_mul(3).ok_or(VoteCollectionError::StakeOverflow)?
            <= total.checked_mul(2).ok_or(VoteCollectionError::StakeOverflow)?
        {
            return Err(VoteCollectionError::InsufficientStake);
        }
        let mut hasher = Shake256::default();
        hasher.update(b"ACTIVECHAIN-VOTE-SET-V1");
        for (key, vote) in &self.votes {
            hasher.update(key);
            hasher.update(&vote.signing_payload());
            hasher.update(vote.signature().as_bytes());
        }
        let mut root = [0_u8; 48];
        sha3::digest::XofReader::read(&mut hasher.finalize_xof(), &mut root);
        let context = ConsensusVoteContext::new_with_revision(
            self.genesis_commitment,
            epoch,
            self.validator_set_root,
            self.protocol_revision,
        )
        .map_err(|_| VoteCollectionError::ContextMismatch)?;
        QuorumCertificate::new(
            context,
            self.proposal.height(),
            self.proposal.round(),
            self.proposal.block_digest(),
            self.proposal.commitment(),
            Digest384::new(root),
            total,
            self.signer_stake,
        )
        .map_err(|_| VoteCollectionError::InsufficientStake)
    }
}
#[derive(Debug, Eq, PartialEq)]
pub enum VoteCollectionError {
    ContextMismatch,
    Duplicate,
    UnknownValidator,
    Verification(VerificationError),
    StakeOverflow,
    InsufficientStake,
}

#[derive(Clone)]
pub struct ValidatorEngine {
    state: ConsensusState,
    genesis_commitment: Digest384,
    validator_set: ValidatorSet,
    public_keys: BTreeMap<activechain_protocol_types::PrincipalId, Vec<u8>>,
    collectors: BTreeMap<Digest384, VoteCollector>,
    timeout_collectors: BTreeMap<TimeoutCollectorKey, TimeoutCollector>,
    current_proposal: Option<Digest384>,
    local_vote_locks: BTreeMap<LocalVoteSlot, Digest384>,
    highest_voted_rounds: BTreeMap<LocalVoteDomain, HighestVotedRound>,
    locked_qc: Option<QuorumCertificate>,
    certified_blocks: BTreeMap<Digest384, CertifiedBlockRecord>,
    active_anchor: ConsensusBlockRef,
    accepted_view_change: Option<ViewChangeCertificate>,
    timeout_locks: BTreeMap<LocalTimeoutDomain, TimeoutSlot>,
}
impl ValidatorEngine {
    pub fn from_genesis(
        state: ConsensusState,
        genesis: &ValidatorGenesis,
    ) -> Result<Self, ValidatorEngineError> {
        Self::from_active_manifest(state, genesis, genesis.genesis_commitment())
    }
    pub fn from_active_manifest(
        state: ConsensusState,
        active_manifest: &ValidatorGenesis,
        chain_genesis_commitment: Digest384,
    ) -> Result<Self, ValidatorEngineError> {
        if state.epoch() != active_manifest.epoch() {
            return Err(ValidatorEngineError::GenesisEpochMismatch);
        }
        if state.validator_set_root() != active_manifest.validator_set_root() {
            return Err(ValidatorEngineError::GenesisRootMismatch);
        }
        if state.protocol_revision() != active_manifest.protocol_revision() {
            return Err(ValidatorEngineError::GenesisRevisionMismatch);
        }
        let validator_set =
            active_manifest.validator_set().map_err(|_| ValidatorEngineError::InvalidGenesis)?;
        let public_keys = active_manifest
            .entries()
            .iter()
            .map(|entry| (entry.validator(), entry.public_key().to_vec()))
            .collect();
        Self::new(state, chain_genesis_commitment, validator_set, public_keys)
    }
    pub fn new(
        state: ConsensusState,
        genesis_commitment: Digest384,
        validator_set: ValidatorSet,
        public_keys: BTreeMap<activechain_protocol_types::PrincipalId, Vec<u8>>,
    ) -> Result<Self, ValidatorEngineError> {
        if genesis_commitment == Digest384::ZERO || state.validator_set_root() == Digest384::ZERO {
            return Err(ValidatorEngineError::UnboundConsensusDomain);
        }
        for validator in validator_set.as_slice() {
            let key = public_keys
                .get(&validator.validator)
                .ok_or(ValidatorEngineError::MissingValidatorKey)?;
            if key.len() != 1312 {
                return Err(ValidatorEngineError::InvalidValidatorKey);
            }
        }
        let active_anchor = state
            .active_anchor(genesis_commitment)
            .map_err(|_| ValidatorEngineError::InvalidFinalizedAnchor)?;
        Ok(Self {
            state,
            genesis_commitment,
            validator_set,
            public_keys,
            collectors: BTreeMap::new(),
            timeout_collectors: BTreeMap::new(),
            current_proposal: None,
            local_vote_locks: BTreeMap::new(),
            highest_voted_rounds: BTreeMap::new(),
            locked_qc: None,
            certified_blocks: BTreeMap::new(),
            active_anchor,
            accepted_view_change: None,
            timeout_locks: BTreeMap::new(),
        })
    }
    pub const fn state(&self) -> ConsensusState {
        self.state
    }
    fn consensus_context(&self) -> Result<ConsensusVoteContext, ValidatorEngineError> {
        ConsensusVoteContext::new_with_revision(
            self.genesis_commitment,
            self.state.epoch(),
            self.state.validator_set_root(),
            self.state.protocol_revision(),
        )
        .map_err(|_| ValidatorEngineError::UnboundConsensusDomain)
    }
    fn finalized_anchor(&self) -> ConsensusBlockRef {
        self.active_anchor
    }
    fn preferred_justification(&self) -> ProposalJustification {
        if let Some(view_change) = &self.accepted_view_change {
            return ProposalJustification::ViewChange(view_change.clone());
        }
        let anchor = self.finalized_anchor();
        self.certified_blocks
            .values()
            .filter(|record| {
                record.certificate.genesis_commitment() == self.genesis_commitment
                    && record.certificate.epoch() == self.state.epoch()
                    && record.certificate.validator_set_root() == self.state.validator_set_root()
                    && record.certificate.protocol_revision() == self.state.protocol_revision()
                    && self.is_ancestor_or_equal(
                        anchor.proposal_commitment(),
                        record.certificate.proposal_commitment(),
                    )
            })
            .max_by_key(|record| {
                (
                    record.certificate.round(),
                    record.certificate.height(),
                    record.certificate.proposal_commitment(),
                )
            })
            .map(|record| ProposalJustification::Quorum(record.certificate.clone()))
            .unwrap_or(ProposalJustification::Finalized(anchor))
    }
    fn active_round_for_height(&self, height: u64) -> Result<u64, ValidatorEngineError> {
        if let Some(view) = &self.accepted_view_change
            && view.height() == height
        {
            return Ok(view.next_round());
        }
        if let Some(round) = self
            .collectors
            .values()
            .filter(|collector| collector.proposal().height() == height)
            .map(|collector| collector.proposal().round())
            .max()
        {
            return Ok(round);
        }
        let parent = self.preferred_justification().parent();
        if parent.height().checked_add(1) != Some(height) {
            return Err(ValidatorEngineError::InvalidViewChange);
        }
        if parent.height() == 0 {
            Ok(parent.round())
        } else {
            parent.round().checked_add(1).ok_or(ValidatorEngineError::RoundOverflow)
        }
    }
    fn admit_timeout_vote(&mut self, vote: TimeoutVote) -> Result<(), ValidatorEngineError> {
        if vote.context() != self.consensus_context()?
            || vote.timed_out_round() != self.active_round_for_height(vote.height())?
        {
            return Err(ValidatorEngineError::InvalidViewChange);
        }
        match vote.highest_qc() {
            Some(qc) => {
                let record = self
                    .certified_blocks
                    .get(&qc.proposal_commitment())
                    .ok_or(ValidatorEngineError::UnknownParentCertificate)?;
                if record.certificate != *qc
                    || vote.parent().block_digest() != qc.block_digest()
                    || vote.parent().proposal_commitment() != qc.proposal_commitment()
                    || vote.parent().height() != qc.height()
                    || vote.parent().round() != qc.round()
                {
                    return Err(ValidatorEngineError::InvalidViewChange);
                }
            }
            None if vote.parent() != self.active_anchor => {
                return Err(ValidatorEngineError::InvalidViewChange);
            }
            None => {}
        }
        let public_key = self
            .public_keys
            .get(&vote.validator())
            .ok_or(ValidatorEngineError::UnknownValidator)?
            .clone();
        let collector_key = TimeoutCollector::from_vote(&vote).key;
        if !self.timeout_collectors.contains_key(&collector_key) {
            if self.timeout_collectors.len() >= MAX_ACTIVE_COLLECTORS {
                return Err(ValidatorEngineError::CollectorLimit);
            }
            self.timeout_collectors.insert(collector_key, TimeoutCollector::from_vote(&vote));
        }
        let collector = self.timeout_collectors.get_mut(&collector_key).unwrap();
        collector.add(vote, &self.validator_set, &public_key)?;
        if let Some(certificate) = collector.certificate(&self.validator_set)? {
            self.verify_view_change(&certificate)?;
            self.accepted_view_change = Some(certificate);
            self.timeout_collectors.retain(|candidate, _| {
                candidate.height > collector_key.height
                    || (candidate.height == collector_key.height
                        && candidate.round > collector_key.round)
            });
        }
        Ok(())
    }
    fn is_ancestor_or_equal(&self, ancestor: Digest384, descendant: Digest384) -> bool {
        let mut cursor = descendant;
        for _ in 0..=self.certified_blocks.len() {
            if cursor == ancestor {
                return true;
            }
            let Some(record) = self.certified_blocks.get(&cursor) else {
                return false;
            };
            cursor = record.parent.proposal_commitment();
        }
        false
    }
    fn verify_proposal_safety(&self, proposal: &BlockProposal) -> Result<(), ValidatorEngineError> {
        let proposer_index = usize::try_from(proposal.round())
            .map_err(|_| ValidatorEngineError::IneligibleProposer)?
            % self.validator_set.as_slice().len();
        if self.validator_set.as_slice()[proposer_index].validator != proposal.proposer() {
            return Err(ValidatorEngineError::IneligibleProposer);
        }
        let parent = proposal.parent();
        match proposal.justification() {
            ProposalJustification::Finalized(candidate) => {
                if *candidate != self.finalized_anchor() {
                    return Err(ValidatorEngineError::InvalidFinalizedAnchor);
                }
            }
            ProposalJustification::Quorum(certificate) => {
                let Some(record) = self.certified_blocks.get(&certificate.proposal_commitment())
                else {
                    return Err(ValidatorEngineError::UnknownParentCertificate);
                };
                if record.certificate != *certificate {
                    return Err(ValidatorEngineError::ConflictingCertificate);
                }
            }
            ProposalJustification::ViewChange(certificate) => {
                self.verify_view_change(certificate)?;
            }
        }
        let finalized = self.finalized_anchor();
        if !self.is_ancestor_or_equal(finalized.proposal_commitment(), parent.proposal_commitment())
        {
            return Err(ValidatorEngineError::ConflictingFinalizedPrefix);
        }
        if let Some(locked) = &self.locked_qc {
            let extends_lock = self
                .is_ancestor_or_equal(locked.proposal_commitment(), parent.proposal_commitment());
            let parent_is_newer = proposal
                .justification()
                .certificate()
                .is_some_and(|parent_qc| parent_qc.round() > locked.round());
            if !extends_lock && !parent_is_newer {
                return Err(ValidatorEngineError::UnsafeProposal);
            }
        }
        Ok(())
    }
    fn verify_view_change(
        &self,
        certificate: &ViewChangeCertificate,
    ) -> Result<(), ValidatorEngineError> {
        if certificate.context() != self.consensus_context()?
            || certificate.parent().height().checked_add(1) != Some(certificate.height())
            || !self.is_ancestor_or_equal(
                self.active_anchor.proposal_commitment(),
                certificate.parent().proposal_commitment(),
            )
        {
            return Err(ValidatorEngineError::InvalidViewChange);
        }
        match certificate.highest_qc() {
            Some(qc) => {
                let record = self
                    .certified_blocks
                    .get(&qc.proposal_commitment())
                    .ok_or(ValidatorEngineError::UnknownParentCertificate)?;
                if record.certificate != *qc
                    || certificate.parent().block_digest() != qc.block_digest()
                    || certificate.parent().proposal_commitment() != qc.proposal_commitment()
                    || certificate.parent().height() != qc.height()
                    || certificate.parent().round() != qc.round()
                {
                    return Err(ValidatorEngineError::InvalidViewChange);
                }
            }
            None if certificate.parent() != self.active_anchor => {
                return Err(ValidatorEngineError::InvalidViewChange);
            }
            None => {}
        }
        for vote in certificate.votes() {
            match vote.highest_qc() {
                Some(qc) => {
                    let record = self
                        .certified_blocks
                        .get(&qc.proposal_commitment())
                        .ok_or(ValidatorEngineError::UnknownParentCertificate)?;
                    if record.certificate != *qc
                        || vote.parent().block_digest() != qc.block_digest()
                        || vote.parent().proposal_commitment() != qc.proposal_commitment()
                        || vote.parent().height() != qc.height()
                        || vote.parent().round() != qc.round()
                        || !self.is_ancestor_or_equal(
                            self.active_anchor.proposal_commitment(),
                            vote.parent().proposal_commitment(),
                        )
                    {
                        return Err(ValidatorEngineError::InvalidViewChange);
                    }
                }
                None if vote.parent() != self.active_anchor => {
                    return Err(ValidatorEngineError::InvalidViewChange);
                }
                None => {}
            }
        }
        let keys: Vec<_> =
            self.public_keys.iter().map(|(validator, key)| (*validator, key.as_slice())).collect();
        verify_view_change_certificate(certificate, &self.validator_set, &keys)
            .map_err(|_| ValidatorEngineError::InvalidViewChange)
    }
    fn validate_restored_safety_state(&self) -> Result<(), ValidatorEngineError> {
        let expected_anchor = self
            .state
            .active_anchor(self.genesis_commitment)
            .map_err(|_| ValidatorEngineError::InvalidSafetySnapshot)?;
        if self.certified_blocks.len() > MAX_PERSISTED_CERTIFIED_BLOCKS
            || self.active_anchor != expected_anchor
        {
            return Err(ValidatorEngineError::InvalidSafetySnapshot);
        }
        if self.local_vote_locks.keys().any(|slot| {
            slot.genesis_commitment != self.genesis_commitment
                || slot.epoch != self.state.epoch()
                || slot.validator_set_root != self.state.validator_set_root()
                || slot.protocol_revision != self.state.protocol_revision()
        }) {
            return Err(ValidatorEngineError::InvalidSafetySnapshot);
        }
        if self.highest_voted_rounds.len() > MAX_PERSISTED_REPLAY_SENDERS
            || self.highest_voted_rounds.iter().any(|(domain, highest)| {
                domain.genesis_commitment != self.genesis_commitment
                    || domain.epoch != self.state.epoch()
                    || domain.validator_set_root != self.state.validator_set_root()
                    || domain.protocol_revision != self.state.protocol_revision()
                    || self.validator_set.stake_of(&domain.validator).is_none()
                    || highest.proposal_commitment == Digest384::ZERO
            })
            || self.local_vote_locks.iter().any(|(slot, commitment)| {
                let domain = LocalVoteDomain {
                    validator: slot.validator,
                    genesis_commitment: slot.genesis_commitment,
                    epoch: slot.epoch,
                    validator_set_root: slot.validator_set_root,
                    protocol_revision: slot.protocol_revision,
                };
                self.highest_voted_rounds.get(&domain).is_none_or(|highest| {
                    highest.round < slot.round
                        || (highest.round == slot.round
                            && (highest.height != slot.height
                                || highest.proposal_commitment != *commitment))
                })
            })
        {
            return Err(ValidatorEngineError::InvalidSafetySnapshot);
        }
        if self.timeout_locks.len() > MAX_PERSISTED_VOTE_LOCKS
            || self.timeout_locks.iter().any(|(domain, slot)| {
                domain.genesis_commitment != self.genesis_commitment
                    || domain.epoch != self.state.epoch()
                    || domain.validator_set_root != self.state.validator_set_root()
                    || domain.protocol_revision != self.state.protocol_revision()
                    || self.validator_set.stake_of(&domain.validator).is_none()
                    || domain.height != slot.height
                    || domain.round != slot.round
                    || slot.parent.height().checked_add(1) != Some(slot.height)
                    || slot.round == u64::MAX
            })
        {
            return Err(ValidatorEngineError::InvalidSafetySnapshot);
        }
        for (digest, record) in &self.certified_blocks {
            let certificate = &record.certificate;
            if *digest != certificate.proposal_commitment()
                || certificate.genesis_commitment() != self.genesis_commitment
                || certificate.epoch() != self.state.epoch()
                || certificate.validator_set_root() != self.state.validator_set_root()
                || certificate.protocol_revision() != self.state.protocol_revision()
                || !self.is_ancestor_or_equal(self.active_anchor.proposal_commitment(), *digest)
            {
                return Err(ValidatorEngineError::InvalidSafetySnapshot);
            }
            let proof = record.proof().map_err(|_| ValidatorEngineError::InvalidSafetySnapshot)?;
            let proposer_key = self
                .public_keys
                .get(&proof.proposal().proposer())
                .ok_or(ValidatorEngineError::InvalidSafetySnapshot)?;
            verify_block_proposal(proposer_key, proof.proposal())
                .map_err(|_| ValidatorEngineError::InvalidSafetySnapshot)?;
            let mut votes = Vec::with_capacity(proof.votes().len());
            for vote in proof.votes() {
                let key = self
                    .public_keys
                    .get(&vote.validator())
                    .ok_or(ValidatorEngineError::InvalidSafetySnapshot)?;
                votes.push((key.as_slice(), vote.clone()));
            }
            verify_quorum_certificate(certificate, &self.validator_set, &votes)
                .map_err(|_| ValidatorEngineError::InvalidSafetySnapshot)?;
        }
        if self.locked_qc.as_ref().is_some_and(|locked| {
            let is_finalized_anchor = locked.block_digest() == self.active_anchor.block_digest()
                && locked.proposal_commitment() == self.active_anchor.proposal_commitment()
                && locked.height() == self.active_anchor.height()
                && locked.round() == self.active_anchor.round();
            !is_finalized_anchor
                && self
                    .certified_blocks
                    .get(&locked.proposal_commitment())
                    .is_none_or(|record| record.certificate != *locked)
        }) {
            return Err(ValidatorEngineError::InvalidSafetySnapshot);
        }
        if let Some(view_change) = &self.accepted_view_change
            && (view_change.height() <= self.state.finalized_height()
                || self.verify_view_change(view_change).is_err())
        {
            return Err(ValidatorEngineError::InvalidSafetySnapshot);
        }
        Ok(())
    }
    pub fn activate_finalized_validator_set(
        &mut self,
        authorization: &ConsensusUpgradeAuthorization,
        authorization_proof: &CertifiedBlock,
        next_genesis: &ValidatorGenesis,
    ) -> Result<(), ValidatorEngineError> {
        if !authorization.changes_validator_set()
            || authorization.to_epoch() != next_genesis.epoch()
            || authorization.activation_height() != next_genesis.activation_height()
            || authorization.next_validator_set_root() != next_genesis.validator_set_root()
            || authorization.next_protocol_revision() != next_genesis.protocol_revision()
        {
            return Err(ValidatorEngineError::InvalidEpochTransition);
        }
        self.verify_finalized_upgrade_authorization(authorization, authorization_proof)?;
        let handoff_anchor = self.upgrade_handoff_anchor(authorization, authorization_proof)?;
        let validator_set =
            next_genesis.validator_set().map_err(|_| ValidatorEngineError::InvalidGenesis)?;
        let public_keys = next_genesis
            .entries()
            .iter()
            .map(|entry| (entry.validator(), entry.public_key().to_vec()))
            .collect();
        let mut next_state = self.state;
        next_state
            .apply_upgrade_after_certified_block(authorization, handoff_anchor)
            .map_err(|_| ValidatorEngineError::InvalidEpochTransition)?;
        self.state = next_state;
        self.validator_set = validator_set;
        self.public_keys = public_keys;
        self.collectors.clear();
        self.timeout_collectors.clear();
        self.current_proposal = None;
        self.local_vote_locks.clear();
        self.highest_voted_rounds.clear();
        self.locked_qc = None;
        self.certified_blocks.clear();
        self.active_anchor = handoff_anchor;
        self.accepted_view_change = None;
        self.timeout_locks.clear();
        Ok(())
    }
    pub fn activate_finalized_protocol_upgrade(
        &mut self,
        authorization: &ConsensusUpgradeAuthorization,
        authorization_proof: &CertifiedBlock,
    ) -> Result<(), ValidatorEngineError> {
        if authorization.changes_validator_set() || !authorization.changes_protocol_revision() {
            return Err(ValidatorEngineError::InvalidProtocolUpgrade);
        }
        self.verify_finalized_upgrade_authorization(authorization, authorization_proof)?;
        let handoff_anchor = self.upgrade_handoff_anchor(authorization, authorization_proof)?;
        self.state
            .apply_upgrade_after_certified_block(authorization, handoff_anchor)
            .map_err(|_| ValidatorEngineError::InvalidProtocolUpgrade)?;
        self.collectors.clear();
        self.timeout_collectors.clear();
        self.current_proposal = None;
        self.local_vote_locks.clear();
        self.highest_voted_rounds.clear();
        self.locked_qc = None;
        self.certified_blocks.clear();
        self.active_anchor = handoff_anchor;
        self.accepted_view_change = None;
        self.timeout_locks.clear();
        Ok(())
    }
    fn verify_finalized_upgrade_authorization(
        &self,
        authorization: &ConsensusUpgradeAuthorization,
        proof: &CertifiedBlock,
    ) -> Result<(), ValidatorEngineError> {
        let certificate = proof.certificate();
        if certificate.height() != authorization.authorization_height()
            || certificate.height() > self.state.finalized_height()
            || certificate.block_digest() != authorization.commitment()
            || certificate.genesis_commitment() != self.genesis_commitment
            || certificate.epoch() != self.state.epoch()
            || certificate.validator_set_root() != self.state.validator_set_root()
            || certificate.protocol_revision() != self.state.protocol_revision()
        {
            return Err(ValidatorEngineError::InvalidUpgradeAuthorizationProof);
        }
        let mut votes = Vec::with_capacity(proof.votes().len());
        for vote in proof.votes() {
            if vote.genesis_commitment() != self.genesis_commitment
                || vote.epoch() != self.state.epoch()
                || vote.validator_set_root() != self.state.validator_set_root()
                || vote.protocol_revision() != self.state.protocol_revision()
            {
                return Err(ValidatorEngineError::InvalidUpgradeAuthorizationProof);
            }
            let key = self
                .public_keys
                .get(&vote.validator())
                .ok_or(ValidatorEngineError::InvalidUpgradeAuthorizationProof)?;
            votes.push((key.as_slice(), vote.clone()));
        }
        verify_quorum_certificate(certificate, &self.validator_set, &votes)
            .map_err(|_| ValidatorEngineError::InvalidUpgradeAuthorizationProof)
    }
    fn upgrade_handoff_anchor(
        &self,
        authorization: &ConsensusUpgradeAuthorization,
        proof: &CertifiedBlock,
    ) -> Result<ConsensusBlockRef, ValidatorEngineError> {
        let authorization_certificate = proof.certificate();
        let authorization_is_finalized_anchor = self.active_anchor.block_digest()
            == authorization_certificate.block_digest()
            && self.active_anchor.proposal_commitment()
                == authorization_certificate.proposal_commitment()
            && self.active_anchor.height() == authorization_certificate.height()
            && self.active_anchor.round() == authorization_certificate.round();
        if !authorization_is_finalized_anchor
            && self
                .certified_blocks
                .get(&authorization_certificate.proposal_commitment())
                .is_none_or(|record| record.certificate != *authorization_certificate)
        {
            return Err(ValidatorEngineError::InvalidUpgradeAuthorizationProof);
        }
        let mut handoffs = self.certified_blocks.values().filter(|record| {
            record.parent.block_digest() == authorization_certificate.block_digest()
                && record.parent.proposal_commitment()
                    == authorization_certificate.proposal_commitment()
                && record.parent.height() == authorization_certificate.height()
                && record.parent.round() == authorization_certificate.round()
                && authorization_certificate.round().checked_add(1)
                    == Some(record.certificate.round())
        });
        let handoff =
            handoffs.next().ok_or(ValidatorEngineError::MissingUpgradeHandoffCertificate)?;
        if handoffs.next().is_some()
            || handoff.certificate.height().checked_add(1)
                != Some(authorization.activation_height())
        {
            return Err(ValidatorEngineError::InvalidUpgradeHandoffCertificate);
        }
        ConsensusBlockRef::new(
            handoff.certificate.block_digest(),
            handoff.certificate.proposal_commitment(),
            handoff.certificate.height(),
            handoff.certificate.round(),
        )
        .map_err(|_| ValidatorEngineError::InvalidUpgradeHandoffCertificate)
    }
    /// Prepares the durable lock and vote-slot transition without invoking a signing key.
    fn prepare_current_vote(
        &mut self,
        validator: PrincipalId,
    ) -> Result<PreparedValidatorVote, ValidatorEngineError> {
        let proposal = self
            .current_proposal
            .and_then(|commitment| self.collectors.get(&commitment))
            .ok_or(ValidatorEngineError::MissingProposal)?
            .proposal()
            .clone();
        if self.validator_set.stake_of(&validator).is_none() {
            return Err(ValidatorEngineError::UnknownValidator);
        }
        self.verify_proposal_safety(&proposal)?;
        let slot = LocalVoteSlot {
            validator,
            genesis_commitment: self.genesis_commitment,
            epoch: proposal.epoch(),
            validator_set_root: self.state.validator_set_root(),
            protocol_revision: self.state.protocol_revision(),
            height: proposal.height(),
            round: proposal.round(),
        };
        let proposal_commitment = proposal.commitment();
        let domain = LocalVoteDomain {
            validator,
            genesis_commitment: self.genesis_commitment,
            epoch: proposal.epoch(),
            validator_set_root: self.state.validator_set_root(),
            protocol_revision: self.state.protocol_revision(),
        };
        match self.highest_voted_rounds.get(&domain) {
            Some(highest) if proposal.round() < highest.round => {
                return Err(ValidatorEngineError::StaleLocalView);
            }
            Some(highest)
                if proposal.round() == highest.round
                    && (proposal.height() != highest.height
                        || proposal_commitment != highest.proposal_commitment) =>
            {
                return Err(ValidatorEngineError::ConflictingLocalVote);
            }
            _ => {}
        }
        match self.local_vote_locks.get(&slot) {
            Some(commitment) if *commitment != proposal_commitment => {
                return Err(ValidatorEngineError::ConflictingLocalVote);
            }
            Some(_) => {}
            None if self.local_vote_locks.len() >= MAX_PERSISTED_VOTE_LOCKS => {
                return Err(ValidatorEngineError::VoteLockLimit);
            }
            None => {
                self.local_vote_locks.insert(slot, proposal_commitment);
            }
        }
        if self
            .highest_voted_rounds
            .get(&domain)
            .is_none_or(|highest| proposal.round() > highest.round)
        {
            self.highest_voted_rounds.insert(
                domain,
                HighestVotedRound {
                    height: proposal.height(),
                    round: proposal.round(),
                    proposal_commitment,
                },
            );
        }
        if let ProposalJustification::Quorum(parent_qc) = proposal.justification()
            && self.locked_qc.as_ref().is_none_or(|locked| parent_qc.round() > locked.round())
        {
            self.locked_qc = Some(parent_qc.clone());
        }
        Ok(PreparedValidatorVote {
            proposal,
            genesis_commitment: self.genesis_commitment,
            validator_set_root: self.state.validator_set_root(),
            protocol_revision: self.state.protocol_revision(),
        })
    }
    fn prepare_timeout_vote(
        &mut self,
        validator: PrincipalId,
        height: u64,
        round: u64,
    ) -> Result<PreparedTimeoutVote, ValidatorEngineError> {
        if self.validator_set.stake_of(&validator).is_none()
            || round != self.active_round_for_height(height)?
        {
            return Err(ValidatorEngineError::InvalidViewChange);
        }
        let justification = self.preferred_justification();
        let parent = justification.parent();
        if parent.height().checked_add(1) != Some(height) {
            return Err(ValidatorEngineError::InvalidViewChange);
        }
        let highest_qc = justification.certificate().cloned();
        let slot = TimeoutSlot {
            height,
            round,
            parent,
            highest_qc: highest_qc
                .as_ref()
                .map_or(Digest384::ZERO, QuorumCertificate::proposal_commitment),
        };
        let context = self.consensus_context()?;
        let domain = LocalTimeoutDomain {
            validator,
            genesis_commitment: context.genesis_commitment(),
            epoch: context.epoch(),
            validator_set_root: context.validator_set_root(),
            protocol_revision: context.protocol_revision(),
            height,
            round,
        };
        match self.timeout_locks.get(&domain) {
            Some(existing) if *existing != slot => {
                return Err(ValidatorEngineError::ConflictingTimeoutVote);
            }
            Some(_) => {}
            None if self.timeout_locks.len() >= MAX_PERSISTED_VOTE_LOCKS => {
                return Err(ValidatorEngineError::VoteLockLimit);
            }
            None => {
                self.timeout_locks.insert(domain, slot);
            }
        }
        Ok(PreparedTimeoutVote { context, height, round, parent, highest_qc })
    }
    /// In-memory helper for unit tests. Authoritative services use durable-before-sign instead.
    #[cfg(test)]
    fn sign_current_vote(
        &mut self,
        signer: &ValidatorSigner,
    ) -> Result<ValidatorVote, ValidatorEngineError> {
        let prepared = self.prepare_current_vote(signer.validator())?;
        signer.sign_prepared_vote(&prepared)
    }
    pub fn process(
        &mut self,
        message: ConsensusMessage,
    ) -> Result<Option<CertifiedBlock>, ValidatorEngineError> {
        match message {
            ConsensusMessage::Proposal(proposal) => {
                let key = self
                    .public_keys
                    .get(&proposal.proposer())
                    .ok_or(ValidatorEngineError::UnknownValidator)?;
                admit_proposal(&self.state, self.genesis_commitment, &proposal, key)
                    .map_err(ValidatorEngineError::Proposal)?;
                self.verify_proposal_safety(&proposal)?;
                if let ProposalJustification::ViewChange(certificate) = proposal.justification() {
                    self.accepted_view_change = Some(certificate.clone());
                }
                let commitment = proposal.commitment();
                if !self.collectors.contains_key(&commitment) {
                    if self.collectors.len() >= MAX_ACTIVE_COLLECTORS {
                        return Err(ValidatorEngineError::CollectorLimit);
                    }
                    self.collectors.insert(
                        commitment,
                        VoteCollector::new(
                            proposal,
                            self.genesis_commitment,
                            self.state.validator_set_root(),
                            self.state.protocol_revision(),
                        ),
                    );
                }
                self.current_proposal = Some(commitment);
                Ok(None)
            }
            ConsensusMessage::Vote(vote) => {
                let key = self
                    .public_keys
                    .get(&vote.validator())
                    .ok_or(ValidatorEngineError::UnknownValidator)?;
                let commitment = vote.proposal_commitment();
                let proof = {
                    let collector = self
                        .collectors
                        .get_mut(&commitment)
                        .ok_or(ValidatorEngineError::MissingProposal)?;
                    collector
                        .add_vote(&self.validator_set, key, vote)
                        .map_err(ValidatorEngineError::Vote)?;
                    match collector.finalize(self.state.epoch(), &self.validator_set) {
                        Ok(certificate) => {
                            let votes: Vec<_> =
                                collector.votes().iter().map(|(_, vote)| vote.clone()).collect();
                            Some(
                                CertifiedBlock::new(
                                    collector.proposal().clone(),
                                    certificate,
                                    votes,
                                )
                                .map_err(ValidatorEngineError::Transport)?,
                            )
                        }
                        Err(VoteCollectionError::InsufficientStake) => None,
                        Err(error) => return Err(ValidatorEngineError::Vote(error)),
                    }
                };
                if let Some(proof) = proof {
                    self.apply_certificate(&proof)?;
                    self.collectors.remove(&commitment);
                    if self.current_proposal == Some(commitment) {
                        self.current_proposal = None;
                    }
                    Ok(Some(proof))
                } else {
                    Ok(None)
                }
            }
            ConsensusMessage::Certificate(proof) => {
                let commitment = proof.certificate().proposal_commitment();
                self.apply_certificate(&proof)?;
                self.collectors.remove(&commitment);
                if self.current_proposal == Some(commitment) {
                    self.current_proposal = None;
                }
                Ok(None)
            }
            ConsensusMessage::CertifiedBlockRequest(commitment) => self
                .certified_blocks
                .get(&commitment)
                .ok_or(ValidatorEngineError::MissingCertifiedHistory)?
                .proof()
                .map(Some)
                .map_err(|_| ValidatorEngineError::InvalidSafetySnapshot),
            ConsensusMessage::TimeoutVote(vote) => {
                self.admit_timeout_vote(vote)?;
                Ok(None)
            }
            ConsensusMessage::ViewChange(certificate) => {
                self.verify_view_change(&certificate)?;
                let current = self.active_round_for_height(certificate.height())?;
                if certificate.next_round() <= current {
                    return Err(ValidatorEngineError::StaleViewChange);
                }
                self.accepted_view_change = Some(certificate);
                Ok(None)
            }
        }
    }
    fn apply_certificate(&mut self, proof: &CertifiedBlock) -> Result<(), ValidatorEngineError> {
        let certificate = proof.certificate();
        let proposal = proof.proposal();
        if certificate.genesis_commitment() != self.genesis_commitment
            || certificate.epoch() != self.state.epoch()
            || certificate.validator_set_root() != self.state.validator_set_root()
            || certificate.protocol_revision() != self.state.protocol_revision()
        {
            return Err(ValidatorEngineError::VoteDomainMismatch);
        }
        let proposer_key = self
            .public_keys
            .get(&proposal.proposer())
            .ok_or(ValidatorEngineError::UnknownValidator)?;
        verify_block_proposal(proposer_key, proposal)
            .map_err(|error| ValidatorEngineError::Proposal(ProposalError::Verification(error)))?;
        let mut votes = Vec::with_capacity(proof.votes().len());
        for vote in proof.votes() {
            if vote.genesis_commitment() != self.genesis_commitment
                || vote.epoch() != self.state.epoch()
                || vote.validator_set_root() != self.state.validator_set_root()
                || vote.protocol_revision() != self.state.protocol_revision()
            {
                return Err(ValidatorEngineError::VoteDomainMismatch);
            }
            let key = self
                .public_keys
                .get(&vote.validator())
                .ok_or(ValidatorEngineError::UnknownValidator)?;
            votes.push((key.as_slice(), vote.clone()));
        }
        verify_quorum_certificate(certificate, &self.validator_set, &votes).map_err(|error| {
            ValidatorEngineError::Runtime(RuntimeError::VoteVerification(error))
        })?;

        self.apply_verified_certificate_transition(proposal, certificate, proof.votes())
    }

    /// Applies a proposal/QC pair after proposal and vote signatures have been verified.
    ///
    /// Kept private so production callers cannot bypass the PQ verification above. Tests use this
    /// transition boundary to exercise thousands of deterministic pruning steps without producing
    /// thousands of expensive ML-DSA signatures.
    fn apply_verified_certificate_transition(
        &mut self,
        proposal: &BlockProposal,
        certificate: &QuorumCertificate,
        votes: &[ValidatorVote],
    ) -> Result<(), ValidatorEngineError> {
        if certificate.genesis_commitment() != self.genesis_commitment
            || certificate.epoch() != self.state.epoch()
            || certificate.validator_set_root() != self.state.validator_set_root()
            || certificate.protocol_revision() != self.state.protocol_revision()
            || certificate.height() != proposal.height()
            || certificate.round() != proposal.round()
            || certificate.block_digest() != proposal.block_digest()
            || certificate.proposal_commitment() != proposal.commitment()
        {
            return Err(ValidatorEngineError::VoteDomainMismatch);
        }

        if let Some(existing) = self.certified_blocks.get(&certificate.proposal_commitment()) {
            if existing.certificate == *certificate && existing.parent == proposal.parent() {
                return Ok(());
            }
            return Err(ValidatorEngineError::ConflictingCertificate);
        }
        self.verify_proposal_safety(proposal)?;
        if self.certified_blocks.len() >= MAX_PERSISTED_CERTIFIED_BLOCKS {
            return Err(ValidatorEngineError::CertifiedBlockLimit);
        }

        let finalized_before = self.state.finalized_height();
        let mut next_state = self.state;
        let mut next_anchor = self.active_anchor;
        if let Some(parent_qc) = proposal.justification().certificate()
            && parent_qc.height().checked_add(1) == Some(certificate.height())
            && parent_qc.round() < certificate.round()
        {
            if parent_qc.height() > next_state.finalized_height() {
                next_state
                    .apply_committed_qc(parent_qc)
                    .map_err(|error| ValidatorEngineError::Runtime(RuntimeError::State(error)))?;
                next_anchor = ConsensusBlockRef::new(
                    parent_qc.block_digest(),
                    parent_qc.proposal_commitment(),
                    parent_qc.height(),
                    parent_qc.round(),
                )
                .map_err(|_| ValidatorEngineError::InvalidFinalizedAnchor)?;
            } else if parent_qc.height() == next_state.finalized_height() {
                if parent_qc.block_digest() != next_state.finalized_block_digest()
                    || parent_qc.proposal_commitment() != next_state.finalized_proposal_commitment()
                {
                    return Err(ValidatorEngineError::ConflictingFinalizedPrefix);
                }
            } else if !self.is_ancestor_or_equal(
                parent_qc.proposal_commitment(),
                next_state.finalized_proposal_commitment(),
            ) {
                return Err(ValidatorEngineError::ConflictingFinalizedPrefix);
            }
        }
        self.certified_blocks.insert(
            certificate.proposal_commitment(),
            CertifiedBlockRecord {
                proposal: proposal.clone(),
                certificate: certificate.clone(),
                votes: votes.to_vec(),
                parent: proposal.parent(),
            },
        );
        self.state = next_state;
        self.active_anchor = next_anchor;
        if self.accepted_view_change.as_ref().is_some_and(|view| {
            view.height() <= self.state.finalized_height()
                || (view.height() == certificate.height()
                    && view.next_round() <= certificate.round())
        }) {
            self.accepted_view_change = None;
        }
        if self.state.finalized_height() > finalized_before {
            self.prune_finalized_history();
        }
        self.local_vote_locks.retain(|slot, _| {
            slot.epoch > self.state.epoch()
                || (slot.epoch == self.state.epoch() && slot.height > self.state.finalized_height())
        });
        self.timeout_locks.retain(|domain, _| {
            domain.epoch > self.state.epoch()
                || (domain.epoch == self.state.epoch()
                    && domain.height > self.state.finalized_height())
        });
        Ok(())
    }

    /// Removes committed ancestry while retaining every certified descendant of the new anchor.
    fn prune_finalized_history(&mut self) {
        let anchor = self.active_anchor;
        let retained: Vec<_> = self
            .certified_blocks
            .iter()
            .filter_map(|(commitment, record)| {
                (record.certificate.height() > anchor.height()
                    && self.is_ancestor_or_equal(anchor.proposal_commitment(), *commitment))
                .then_some(*commitment)
            })
            .collect();
        self.certified_blocks.retain(|commitment, _| retained.binary_search(commitment).is_ok());
        if self.locked_qc.as_ref().is_some_and(|locked| locked.height() <= anchor.height()) {
            self.locked_qc = None;
        }
    }
}

#[derive(Debug)]
pub enum ValidatorEngineError {
    InvalidGenesis,
    InvalidEpochTransition,
    InvalidProtocolUpgrade,
    InvalidUpgradeAuthorizationProof,
    MissingUpgradeHandoffCertificate,
    InvalidUpgradeHandoffCertificate,
    GenesisEpochMismatch,
    GenesisRootMismatch,
    GenesisRevisionMismatch,
    SnapshotDomainMismatch,
    SnapshotStateMismatch,
    SnapshotUnknownSender,
    MissingValidatorKey,
    InvalidValidatorKey,
    UnboundConsensusDomain,
    UnknownValidator,
    MissingProposal,
    ConflictingLocalVote,
    ConflictingTimeoutVote,
    StaleLocalView,
    VoteDomainMismatch,
    VoteLockLimit,
    CollectorLimit,
    CertifiedBlockLimit,
    InvalidFinalizedAnchor,
    InvalidCashSnapshot,
    UnknownParentCertificate,
    MissingCertifiedHistory,
    ConflictingCertificate,
    ConflictingFinalizedPrefix,
    UnsafeProposal,
    InvalidSafetySnapshot,
    InvalidViewChange,
    IneligibleProposer,
    DuplicateTimeoutVote,
    StaleViewChange,
    SequenceOverflow,
    HeightOverflow,
    RoundOverflow,
    Proposal(ProposalError),
    Vote(VoteCollectionError),
    Transport(TransportError),
    Runtime(RuntimeError),
    Snapshot(std::io::Error),
    Signer,
}

pub struct ValidatorService {
    engine: std::sync::Mutex<ValidatorEngine>,
    replay: std::sync::Mutex<ReplayGuard>,
    outbound_high_water: std::sync::Mutex<BTreeMap<u16, u64>>,
    sender_keys: std::sync::Mutex<BTreeMap<u16, Vec<u8>>>,
    snapshot_path: std::path::PathBuf,
    session_store: Arc<Mutex<PqSessionStore>>,
    session_store_path: std::path::PathBuf,
    metrics: std::sync::Arc<ValidatorMetrics>,
    authenticated_rate_limits: std::sync::Mutex<BTreeMap<u16, (Instant, usize)>>,
}
impl ValidatorService {
    pub fn from_genesis(
        state: ConsensusState,
        genesis: &ValidatorGenesis,
        snapshot_path: std::path::PathBuf,
    ) -> Result<Self, ValidatorEngineError> {
        Self::from_active_manifest(state, genesis, genesis.genesis_commitment(), snapshot_path)
    }
    pub fn from_active_manifest(
        state: ConsensusState,
        active_manifest: &ValidatorGenesis,
        chain_genesis_commitment: Digest384,
        snapshot_path: std::path::PathBuf,
    ) -> Result<Self, ValidatorEngineError> {
        let sender_keys = active_manifest
            .entries()
            .iter()
            .enumerate()
            .map(|(index, entry)| ((index + 1) as u16, entry.public_key().to_vec()))
            .collect::<BTreeMap<_, _>>();
        let mut engine = ValidatorEngine::from_active_manifest(
            state,
            active_manifest,
            chain_genesis_commitment,
        )?;
        let mut replay = ReplayGuard::default();
        let mut outbound_high_water = BTreeMap::new();
        let mut migrated_snapshot = false;
        match std::fs::read(&snapshot_path) {
            Ok(bytes) => match decode_validator_snapshot(&bytes) {
                Ok((persisted, migrated)) => {
                    if persisted.genesis_commitment != engine.genesis_commitment {
                        return Err(ValidatorEngineError::SnapshotDomainMismatch);
                    }
                    if ConsensusState::from_snapshot(persisted.consensus) != state {
                        return Err(ValidatorEngineError::SnapshotStateMismatch);
                    }
                    if persisted
                        .replay_high_water
                        .keys()
                        .chain(persisted.outbound_high_water.keys())
                        .any(|sender| !sender_keys.contains_key(sender))
                    {
                        return Err(ValidatorEngineError::SnapshotUnknownSender);
                    }
                    engine.local_vote_locks = persisted.vote_locks;
                    engine.highest_voted_rounds = persisted.highest_voted_rounds;
                    engine.locked_qc = persisted.locked_qc;
                    engine.certified_blocks = persisted.certified_blocks;
                    engine.active_anchor = persisted.active_anchor;
                    engine.accepted_view_change = persisted.accepted_view_change;
                    engine.timeout_locks = persisted.timeout_locks;
                    engine.validate_restored_safety_state()?;
                    replay.highest = persisted.replay_high_water;
                    outbound_high_water = persisted.outbound_high_water;
                    migrated_snapshot = migrated;
                }
                Err(_) if bytes.starts_with(&PersistedValidatorState::TYPE_TAG.to_be_bytes()) => {
                    return Err(ValidatorEngineError::Snapshot(invalid_data(
                        "validator safety snapshot is invalid",
                    )));
                }
                Err(_) => {}
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ValidatorEngineError::Snapshot(error)),
        }
        if migrated_snapshot {
            save_validator_snapshot(&snapshot_path, &engine, &replay, &outbound_high_water)
                .map_err(ValidatorEngineError::Snapshot)?;
        }
        let session_store_path = snapshot_path.with_extension("sessions");
        let session_store = PqSessionStore::load_or_new(
            &session_store_path,
            engine.genesis_commitment,
            engine.state.epoch(),
            engine.state.protocol_revision(),
        )
        .map_err(ValidatorEngineError::Snapshot)?;
        Ok(Self {
            engine: std::sync::Mutex::new(engine),
            replay: std::sync::Mutex::new(replay),
            outbound_high_water: std::sync::Mutex::new(outbound_high_water),
            sender_keys: std::sync::Mutex::new(sender_keys),
            snapshot_path,
            session_store: Arc::new(Mutex::new(session_store)),
            session_store_path,
            metrics: std::sync::Arc::new(ValidatorMetrics::default()),
            authenticated_rate_limits: std::sync::Mutex::new(BTreeMap::new()),
        })
    }
    fn session_context(&self, initiator: u16, responder: u16) -> std::io::Result<PqSessionContext> {
        let engine =
            self.engine.lock().map_err(|_| invalid_data("validator engine lock poisoned"))?;
        if !self
            .sender_keys
            .lock()
            .map_err(|_| invalid_data("validator sender-key lock poisoned"))?
            .contains_key(&initiator)
            || !self
                .sender_keys
                .lock()
                .map_err(|_| invalid_data("validator sender-key lock poisoned"))?
                .contains_key(&responder)
        {
            return Err(invalid_data("unknown PQ session peer"));
        }
        Ok(PqSessionContext {
            chain: engine.genesis_commitment,
            epoch: engine.state.epoch(),
            protocol_revision: engine.state.protocol_revision(),
            initiator,
            responder,
        })
    }
    fn accept_session(&self, session: &PqPeerSession) -> std::io::Result<()> {
        self.session_store
            .lock()
            .map_err(|_| invalid_data("PQ session store lock poisoned"))?
            .accept_and_save(session, &self.session_store_path)
    }
    fn record_peer_session_established(&self) {
        self.metrics.peer_sessions_established.fetch_add(1, Ordering::Relaxed);
    }
    fn record_peer_session_rejection(&self) {
        self.metrics.peer_session_rejections.fetch_add(1, Ordering::Relaxed);
    }
    fn record_peer_io_error(&self, error: &std::io::Error) {
        match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                self.metrics.peer_timeouts.fetch_add(1, Ordering::Relaxed);
            }
            std::io::ErrorKind::InvalidData => {
                self.metrics.peer_malformed_frames.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
    fn allow_authenticated_receive(&self, peer_id: u16, now: Instant) -> std::io::Result<bool> {
        let mut limits = self
            .authenticated_rate_limits
            .lock()
            .map_err(|_| invalid_data("authenticated rate-limit lock poisoned"))?;
        let entry = limits.entry(peer_id).or_insert((now, 0));
        if now.saturating_duration_since(entry.0) >= Duration::from_secs(1) {
            *entry = (now, 0);
        }
        if entry.1 >= MAX_AUTHENTICATED_MESSAGES_PER_SECOND {
            self.metrics.peer_rate_limited.fetch_add(1, Ordering::Relaxed);
            eprintln!("peer_ingress event=authenticated_rate_limited peer={peer_id}");
            return Ok(false);
        }
        entry.1 += 1;
        Ok(true)
    }
    pub fn state(&self) -> Result<ConsensusState, ValidatorServiceError> {
        self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned).map(|engine| engine.state())
    }

    /// Returns the durable certificate material for an exact finalized block digest. This is used
    /// by crash recovery to finish a precommitted publication after consensus persisted first.
    pub fn certified_block(
        &self,
        block_digest: Digest384,
    ) -> Result<Option<CertifiedBlock>, ValidatorServiceError> {
        let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        engine
            .certified_blocks
            .values()
            .find(|record| record.certificate.block_digest() == block_digest)
            .map(CertifiedBlockRecord::proof)
            .transpose()
            .map_err(ValidatorServiceError::Transport)
    }
    /// Persists an execution-produced cash snapshot only when it exactly matches this validator's
    /// finalized consensus identity and height. Execution remains the source of Coin Cells; this
    /// boundary prevents an operator from publishing an optimistic or cross-chain snapshot.
    pub fn persist_finalized_cash_snapshot(
        &self,
        path: &std::path::Path,
        snapshot: &FinalizedCashSnapshot,
    ) -> Result<(), ValidatorServiceError> {
        let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        if snapshot.chain_genesis != engine.genesis_commitment
            || snapshot.finalized_height != engine.state.finalized_height()
            || snapshot.verify().is_err()
        {
            return Err(ValidatorServiceError::Engine(ValidatorEngineError::InvalidCashSnapshot));
        }
        snapshot
            .save(path)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)
    }

    /// Persists execution cash only after binding it to the exact finalized
    /// certificate. This is the production RPC publication boundary.
    pub fn persist_finalized_cash_snapshot_with_finality(
        &self,
        path: &std::path::Path,
        snapshot: &FinalizedCashSnapshot,
        finality: &[u8],
    ) -> Result<(), ValidatorServiceError> {
        let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        if snapshot.chain_genesis != engine.genesis_commitment
            || snapshot.finalized_height != engine.state.finalized_height()
            || snapshot.verify_against_finality(finality).is_err()
        {
            return Err(ValidatorServiceError::Engine(ValidatorEngineError::InvalidCashSnapshot));
        }
        snapshot
            .save_with_finality(path, finality)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)
    }

    /// Builds proof-bearing RPC records from execution state only after the exact
    /// finalized certificate has authenticated the snapshot root and height.
    pub fn finalized_cash_rpc_records(
        &self,
        snapshot: &FinalizedCashSnapshot,
        finality: &[u8],
    ) -> Result<Vec<QueryRecord>, ValidatorServiceError> {
        let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        if snapshot.chain_genesis != engine.genesis_commitment
            || snapshot.finalized_height != engine.state.finalized_height()
            || snapshot.verify_against_finality(finality).is_err()
        {
            return Err(ValidatorServiceError::Engine(ValidatorEngineError::InvalidCashSnapshot));
        }
        finalized_coin_cell_records_with_chain_genesis(
            &snapshot.cells,
            snapshot.finalized_height,
            finality,
            snapshot.chain_genesis,
        )
        .map_err(|_| ValidatorServiceError::Engine(ValidatorEngineError::InvalidCashSnapshot))
    }

    /// Materializes the execution wallet ledger and publishes its finalized,
    /// proof-bearing records in one validator-bound operation. The finality
    /// certificate remains mandatory; no optimistic wallet state can cross the
    /// RPC boundary through this helper.
    pub fn finalized_cash_rpc_records_from_wallet(
        &self,
        wallet: &WalletTransactionGateway,
        finality: &[u8],
    ) -> Result<Vec<QueryRecord>, ValidatorServiceError> {
        let (genesis, height) = {
            let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
            (engine.genesis_commitment, engine.state.finalized_height())
        };
        let snapshot = wallet.finalized_cash_snapshot(genesis, height).map_err(|_| {
            ValidatorServiceError::Engine(ValidatorEngineError::InvalidCashSnapshot)
        })?;
        self.finalized_cash_rpc_records(&snapshot, finality)
    }
    pub fn activate_finalized_validator_set(
        &self,
        authorization: &ConsensusUpgradeAuthorization,
        authorization_proof: &CertifiedBlock,
        next_genesis: &ValidatorGenesis,
    ) -> Result<(), ValidatorServiceError> {
        let mut engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut sender_keys =
            self.sender_keys.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut candidate = engine.clone();
        candidate
            .activate_finalized_validator_set(authorization, authorization_proof, next_genesis)
            .map_err(ValidatorServiceError::Engine)?;
        save_validator_snapshot(&self.snapshot_path, &candidate, &replay, &outbound)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *sender_keys = next_genesis
            .entries()
            .iter()
            .enumerate()
            .map(|(index, entry)| ((index + 1) as u16, entry.public_key().to_vec()))
            .collect();
        *engine = candidate;
        Ok(())
    }
    pub fn activate_finalized_protocol_upgrade(
        &self,
        authorization: &ConsensusUpgradeAuthorization,
        authorization_proof: &CertifiedBlock,
    ) -> Result<(), ValidatorServiceError> {
        let mut engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut candidate = engine.clone();
        candidate
            .activate_finalized_protocol_upgrade(authorization, authorization_proof)
            .map_err(ValidatorServiceError::Engine)?;
        save_validator_snapshot(&self.snapshot_path, &candidate, &replay, &outbound)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *engine = candidate;
        Ok(())
    }
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }
    pub fn next_sequence(&self, sender: u16) -> Result<u64, ValidatorServiceError> {
        if !self
            .sender_keys
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .contains_key(&sender)
        {
            return Err(ValidatorServiceError::UnknownSender);
        }
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        replay
            .highest
            .get(&sender)
            .copied()
            .into_iter()
            .chain(outbound.get(&sender).copied())
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))
    }
    pub fn next_proposal_position(&self) -> Result<(u64, u64), ValidatorServiceError> {
        let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let justification = engine.preferred_justification();
        if let ProposalJustification::ViewChange(certificate) = &justification {
            return Ok((certificate.height(), certificate.next_round()));
        }
        let parent = justification.parent();
        let height = parent
            .height()
            .checked_add(1)
            .ok_or(ValidatorServiceError::Engine(ValidatorEngineError::HeightOverflow))?;
        let round = if parent.height() == 0 {
            parent.round()
        } else {
            parent
                .round()
                .checked_add(1)
                .ok_or(ValidatorServiceError::Engine(ValidatorEngineError::RoundOverflow))?
        };
        Ok((height, round))
    }
    fn reserve_sequence_range(
        &self,
        sender: u16,
        first: u64,
        count: u64,
    ) -> Result<(), ValidatorServiceError> {
        if count == 0
            || !self
                .sender_keys
                .lock()
                .map_err(|_| ValidatorServiceError::Poisoned)?
                .contains_key(&sender)
        {
            return Err(ValidatorServiceError::UnknownSender);
        }
        let last = first
            .checked_add(count - 1)
            .ok_or(ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))?;
        let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let highest = replay
            .highest
            .get(&sender)
            .copied()
            .into_iter()
            .chain(outbound.get(&sender).copied())
            .max()
            .unwrap_or(0);
        if first <= highest {
            return Err(ValidatorServiceError::Transport(TransportError::Replay));
        }
        let mut candidate = outbound.clone();
        candidate.insert(sender, last);
        save_validator_snapshot(&self.snapshot_path, &engine, &replay, &candidate)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *outbound = candidate;
        Ok(())
    }
    pub fn process_message(
        &self,
        message: AuthenticatedConsensusMessage,
    ) -> Result<Option<CertifiedBlock>, ValidatorServiceError> {
        match &message.message {
            ConsensusMessage::Proposal(_) => {
                self.metrics.proposals.fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMessage::Vote(_) => {
                self.metrics.votes.fetch_add(1, Ordering::Relaxed);
            }
            ConsensusMessage::Certificate(_) => {}
            ConsensusMessage::CertifiedBlockRequest(_) => {}
            ConsensusMessage::TimeoutVote(_) => {}
            ConsensusMessage::ViewChange(_) => {}
        }
        let key = self
            .sender_keys
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .get(&message.envelope.sender())
            .cloned()
            .ok_or(ValidatorServiceError::UnknownSender)?;
        let mut engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut candidate_replay = replay.clone();
        candidate_replay
            .accept(&message.envelope, &key)
            .map_err(ValidatorServiceError::Transport)?;
        save_validator_snapshot(&self.snapshot_path, &engine, &candidate_replay, &outbound)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *replay = candidate_replay;

        let mut candidate_engine = engine.clone();
        let finalized_before = engine.state.finalized_height();
        let result =
            candidate_engine.process(message.message).map_err(ValidatorServiceError::Engine);
        let finalized_advanced =
            result.is_ok() && candidate_engine.state.finalized_height() > finalized_before;
        if result.is_ok() {
            save_validator_snapshot(&self.snapshot_path, &candidate_engine, &replay, &outbound)
                .map_err(ValidatorEngineError::Snapshot)
                .map_err(ValidatorServiceError::Engine)?;
            *engine = candidate_engine;
        }
        if finalized_advanced {
            self.metrics.finalized_certificates.fetch_add(1, Ordering::Relaxed);
        }
        if result.is_err() {
            self.metrics.rejected_messages.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn sign_current_vote_durably<S: ConsensusVoteSigner>(
        &self,
        signer: &S,
    ) -> Result<ValidatorVote, ValidatorServiceError> {
        let mut engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut candidate = engine.clone();
        let prepared = candidate
            .prepare_current_vote(signer.validator())
            .map_err(ValidatorServiceError::Engine)?;
        save_validator_snapshot(&self.snapshot_path, &candidate, &replay, &outbound)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *engine = candidate;
        // The exact vote slot and any parent lock are durable before key use. Keep the engine lock
        // until signing completes so an epoch transition cannot race an old-context signature.
        drop(outbound);
        drop(replay);
        let vote = signer.sign_prepared_vote(&prepared).map_err(ValidatorServiceError::Engine)?;
        drop(engine);
        Ok(vote)
    }
    /// Durably locks one exact timeout vote before invoking the validator signing key.
    pub fn timeout_round(
        &self,
        signer: &ValidatorSigner,
        height: u64,
        round: u64,
        sequence: u64,
    ) -> Result<AuthenticatedConsensusMessage, ValidatorServiceError> {
        let sender = self.sender_for(signer)?;
        self.reserve_sequence_range(sender, sequence, 1)?;
        let mut engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let replay = self.replay.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let outbound =
            self.outbound_high_water.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
        let mut candidate = engine.clone();
        let prepared = candidate
            .prepare_timeout_vote(signer.validator(), height, round)
            .map_err(ValidatorServiceError::Engine)?;
        save_validator_snapshot(&self.snapshot_path, &candidate, &replay, &outbound)
            .map_err(ValidatorEngineError::Snapshot)
            .map_err(ValidatorServiceError::Engine)?;
        *engine = candidate;
        drop(outbound);
        drop(replay);
        let vote = signer
            .sign_timeout_vote(
                prepared.context,
                prepared.height,
                prepared.round,
                prepared.parent,
                prepared.highest_qc,
            )
            .map_err(ValidatorServiceError::Engine)?;
        drop(engine);
        let message = signer
            .sign_envelope(sender, sequence, ConsensusMessage::TimeoutVote(vote))
            .map_err(ValidatorServiceError::Engine)?;
        self.process_message(message.clone())?;
        Ok(message)
    }
    pub fn timeout_round_and_broadcast(
        &self,
        signer: &ValidatorSigner,
        height: u64,
        round: u64,
        sequence: u64,
        peers: &mut PeerDirectory,
    ) -> Result<(), ValidatorServiceError> {
        let message = self.timeout_round(signer, height, round, sequence)?;
        peers.broadcast_message(&message).map_err(ValidatorServiceError::Io)
    }
    /// Publishes the exact durable timeout quorum for peers that missed individual timeout votes.
    pub fn publish_view_change(
        &self,
        signer: &ValidatorSigner,
        sequence: u64,
    ) -> Result<AuthenticatedConsensusMessage, ValidatorServiceError> {
        let sender = self.sender_for(signer)?;
        self.reserve_sequence_range(sender, sequence, 1)?;
        let certificate = self
            .engine
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .accepted_view_change
            .clone()
            .ok_or(ValidatorServiceError::Engine(ValidatorEngineError::InvalidViewChange))?;
        signer
            .sign_envelope(sender, sequence, ConsensusMessage::ViewChange(certificate))
            .map_err(ValidatorServiceError::Engine)
    }
    pub fn process_proposal_and_sign_vote(
        &self,
        proposal: AuthenticatedConsensusMessage,
        signer: &ValidatorSigner,
        sequence: u64,
    ) -> Result<AuthenticatedConsensusMessage, ValidatorServiceError> {
        self.process_message(proposal)?;
        let sender = self.sender_for(signer)?;
        self.reserve_sequence_range(sender, sequence, 1)?;
        let vote = self.sign_current_vote_durably(signer)?;
        signer
            .sign_envelope(sender, sequence, ConsensusMessage::Vote(vote))
            .map_err(ValidatorServiceError::Engine)
    }
    pub fn request_certified_block(
        &self,
        signer: &ValidatorSigner,
        commitment: Digest384,
        sequence: u64,
    ) -> Result<AuthenticatedConsensusMessage, ValidatorServiceError> {
        let sender = self.sender_for(signer)?;
        self.reserve_sequence_range(sender, sequence, 1)?;
        signer
            .sign_envelope(sender, sequence, ConsensusMessage::CertifiedBlockRequest(commitment))
            .map_err(ValidatorServiceError::Engine)
    }
    pub fn process_certified_block_request_and_sign_response(
        &self,
        request: AuthenticatedConsensusMessage,
        signer: &ValidatorSigner,
        sequence: u64,
    ) -> Result<AuthenticatedConsensusMessage, ValidatorServiceError> {
        if !matches!(&request.message, ConsensusMessage::CertifiedBlockRequest(_)) {
            return Err(ValidatorServiceError::Engine(
                ValidatorEngineError::MissingCertifiedHistory,
            ));
        }
        let proof = self
            .process_message(request)?
            .ok_or(ValidatorServiceError::Engine(ValidatorEngineError::MissingCertifiedHistory))?;
        let sender = self.sender_for(signer)?;
        self.reserve_sequence_range(sender, sequence, 1)?;
        signer
            .sign_envelope(sender, sequence, ConsensusMessage::Certificate(proof))
            .map_err(ValidatorServiceError::Engine)
    }
    pub fn propose_round(
        &self,
        signer: &ValidatorSigner,
        height: u64,
        round: u64,
        block_digest: Digest384,
        sequence: u64,
    ) -> Result<(AuthenticatedConsensusMessage, AuthenticatedConsensusMessage), ValidatorServiceError>
    {
        let (context, justification) = {
            let engine = self.engine.lock().map_err(|_| ValidatorServiceError::Poisoned)?;
            (
                engine.consensus_context().map_err(ValidatorServiceError::Engine)?,
                engine.preferred_justification(),
            )
        };
        let proposal = signer
            .sign_proposal(context, height, round, block_digest, justification)
            .map_err(ValidatorServiceError::Engine)?;
        let sender = self.sender_for(signer)?;
        self.reserve_sequence_range(sender, sequence, 2)?;
        let proposal_message = signer
            .sign_envelope(sender, sequence, ConsensusMessage::Proposal(proposal))
            .map_err(ValidatorServiceError::Engine)?;
        self.process_message(proposal_message.clone())?;
        let vote = self.sign_current_vote_durably(signer)?;
        let vote_sequence = sequence
            .checked_add(1)
            .ok_or(ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))?;
        let vote_message = signer
            .sign_envelope(sender, vote_sequence, ConsensusMessage::Vote(vote))
            .map_err(ValidatorServiceError::Engine)?;
        self.process_message(vote_message.clone())?;
        Ok((proposal_message, vote_message))
    }
    /// Propose, self-process, and fan out a complete round to authenticated peers.
    ///
    /// The local service finalizes from its own quorum rules; peers receive the
    /// same canonical proposal and vote bodies through the bounded directory.
    pub fn propose_round_and_broadcast(
        &self,
        signer: &ValidatorSigner,
        height: u64,
        round: u64,
        block_digest: Digest384,
        sequence: u64,
        peers: &mut PeerDirectory,
    ) -> Result<(), ValidatorServiceError> {
        let (proposal, vote) = self.propose_round(signer, height, round, block_digest, sequence)?;
        peers.broadcast_message(&proposal).map_err(ValidatorServiceError::Io)?;
        peers.broadcast_message(&vote).map_err(ValidatorServiceError::Io)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn propose_round_collect_votes(
        &self,
        signer: &ValidatorSigner,
        height: u64,
        round: u64,
        block_digest: Digest384,
        sequence: u64,
        peers: &mut PeerDirectory,
        peer_ids: &[u16],
    ) -> Result<ConsensusState, ValidatorServiceError> {
        self.propose_round_collect_votes_with_certificate(
            signer,
            height,
            round,
            block_digest,
            sequence,
            peers,
            peer_ids,
        )
        .map(|(state, _)| state)
    }

    /// Proposes a round and returns the exact certified block used to advance
    /// finality. Deployment publishers use this variant to construct a
    /// verifier-consumable finality bundle without scraping internal state.
    #[allow(clippy::too_many_arguments)]
    pub fn propose_round_collect_votes_with_certificate(
        &self,
        signer: &ValidatorSigner,
        height: u64,
        round: u64,
        block_digest: Digest384,
        sequence: u64,
        peers: &mut PeerDirectory,
        peer_ids: &[u16],
    ) -> Result<(ConsensusState, Option<CertifiedBlock>), ValidatorServiceError> {
        let (proposal, own_vote) =
            self.propose_round(signer, height, round, block_digest, sequence)?;
        peers.broadcast_message(&proposal).map_err(ValidatorServiceError::Io)?;
        peers.broadcast_message(&own_vote).map_err(ValidatorServiceError::Io)?;
        let mut certificate = None;
        for peer_id in peer_ids {
            let vote = peers.receive_verified(*peer_id).map_err(|error| match error {
                PeerReceiveError::Io(io) => ValidatorServiceError::Io(io),
                PeerReceiveError::Transport(transport) => {
                    ValidatorServiceError::Transport(transport)
                }
                PeerReceiveError::UnknownPeer => ValidatorServiceError::UnknownSender,
            })?;
            if let Some(proof) = self.process_message(vote)? {
                certificate = Some(proof);
            }
        }
        if let Some(proof) = certificate.as_ref() {
            let sender = self.sender_for(signer)?;
            let certificate_sequence = sequence
                .checked_add(2)
                .ok_or(ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))?;
            self.reserve_sequence_range(sender, certificate_sequence, 1)?;
            let message = signer
                .sign_envelope(
                    sender,
                    certificate_sequence,
                    ConsensusMessage::Certificate(proof.clone()),
                )
                .map_err(ValidatorServiceError::Engine)?;
            peers.broadcast_message(&message).map_err(ValidatorServiceError::Io)?;
        }
        self.state().map(|state| (state, certificate))
    }
    fn sender_for(&self, signer: &ValidatorSigner) -> Result<u16, ValidatorServiceError> {
        let public_key = signer.public_key();
        self.sender_keys
            .lock()
            .map_err(|_| ValidatorServiceError::Poisoned)?
            .iter()
            .find_map(|(sender, key)| (key == &public_key).then_some(*sender))
            .ok_or(ValidatorServiceError::UnknownSender)
    }
    fn authenticate_inbound_peer(
        &self,
        mut peer: PeerSocket,
        local_peer_id: u16,
        signer: &ValidatorSigner,
    ) -> std::io::Result<(PeerSocket, PqPeerSession)> {
        let result = (|| {
            if self.sender_for(signer).map_err(|_| invalid_data("unknown local session signer"))?
                != local_peer_id
            {
                return Err(invalid_data("local session signer identity mismatch"));
            }
            peer.set_timeouts(Some(PEER_FRAME_DEADLINE), Some(PEER_FRAME_DEADLINE))?;
            peer.set_absolute_deadline(Some(Instant::now() + PEER_FRAME_DEADLINE));
            let (chain, epoch, protocol_revision, peer_keys) = {
                let engine = self
                    .engine
                    .lock()
                    .map_err(|_| invalid_data("validator engine lock poisoned"))?;
                let keys = self
                    .sender_keys
                    .lock()
                    .map_err(|_| invalid_data("validator sender-key lock poisoned"))?
                    .clone();
                (
                    engine.genesis_commitment,
                    engine.state.epoch(),
                    engine.state.protocol_revision(),
                    keys,
                )
            };
            let session = peer.accept_pq_session(
                chain,
                epoch,
                protocol_revision,
                local_peer_id,
                signer,
                &peer_keys,
            )?;
            self.accept_session(&session)?;
            peer.set_absolute_deadline(Some(Instant::now() + PEER_SESSION_LIFETIME));
            peer.set_timeouts(Some(PEER_SESSION_IDLE_TIMEOUT), Some(PEER_FRAME_DEADLINE))?;
            Ok((peer, session))
        })();
        match result {
            Ok(connection) => {
                self.record_peer_session_established();
                Ok(connection)
            }
            Err(error) => {
                self.record_peer_session_rejection();
                self.record_peer_io_error(&error);
                Err(error)
            }
        }
    }
    fn receive_session_message(
        &self,
        peer: &mut PeerSocket,
        session: &PqPeerSession,
    ) -> std::io::Result<AuthenticatedConsensusMessage> {
        if !self.allow_authenticated_receive(session.peer, Instant::now())? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "authenticated peer rate limited",
            ));
        }
        let (session_sequence, message) = match peer.receive_protected_message(session) {
            Ok(received) => received,
            Err(error) => {
                self.record_peer_io_error(&error);
                return Err(error);
            }
        };
        if message.envelope.sender() != session.peer {
            return Err(invalid_data("protected frame sender does not match session peer"));
        }
        self.session_store
            .lock()
            .map_err(|_| invalid_data("PQ session store lock poisoned"))?
            .accept_receive_and_save(session.id, session_sequence, &self.session_store_path)?;
        Ok(message)
    }
    fn enforce_session_bounds(started: Instant, messages: usize) -> std::io::Result<()> {
        if messages >= MAX_PEER_SESSION_MESSAGES {
            return Err(invalid_data("authenticated peer session message limit reached"));
        }
        if started.elapsed() >= PEER_SESSION_LIFETIME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "authenticated peer session lifetime exceeded",
            ));
        }
        Ok(())
    }
    pub fn serve_authenticated_genesis_peer(
        &self,
        peer: PeerSocket,
        local_peer_id: u16,
        signer: &ValidatorSigner,
    ) -> std::io::Result<()> {
        let (mut peer, session) = self.authenticate_inbound_peer(peer, local_peer_id, signer)?;
        let started = Instant::now();
        let mut messages = 0;
        loop {
            Self::enforce_session_bounds(started, messages)?;
            let message = match self.receive_session_message(&mut peer, &session) {
                Ok(message) => message,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            };
            messages += 1;
            self.process_message(message).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{error:?}"))
            })?;
        }
    }
    pub fn serve_authenticated_genesis_peer_with_voting(
        &self,
        peer: PeerSocket,
        local_peer_id: u16,
        signer: &ValidatorSigner,
    ) -> std::io::Result<()> {
        let (mut peer, session) = self.authenticate_inbound_peer(peer, local_peer_id, signer)?;
        let started = Instant::now();
        let mut messages = 0;
        loop {
            Self::enforce_session_bounds(started, messages)?;
            let message = match self.receive_session_message(&mut peer, &session) {
                Ok(message) => message,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            };
            messages += 1;
            if let ConsensusMessage::Proposal(_) = &message.message {
                let sequence = self
                    .next_sequence(local_peer_id)
                    .map_err(|_| invalid_data("local durable outbound sequence unavailable"))?;
                let vote = self
                    .process_proposal_and_sign_vote(message.clone(), signer, sequence)
                    .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("proposal admission failed: {error:?}"),
                    )
                })?;
                let session_sequence = self
                    .session_store
                    .lock()
                    .map_err(|_| invalid_data("PQ session store lock poisoned"))?
                    .reserve_send_and_save(session.id, &self.session_store_path)?;
                peer.send_protected_message(&session, session_sequence, &vote)?;
            } else {
                self.process_message(message)
                    .map_err(|_| invalid_data("consensus admission failed"))?;
            }
        }
    }
}
#[derive(Debug)]
pub enum ValidatorServiceError {
    UnknownSender,
    Poisoned,
    Io(std::io::Error),
    Transport(TransportError),
    Engine(ValidatorEngineError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_canonical_codec::encode_envelope;
    use activechain_cash_kernel::CoinTransfer;
    use activechain_cash_kernel::{GenesisAllocation, GenesisEconomy, NativeAssetDefinition};
    use activechain_protocol_types::{
        AuthenticatorDescriptor, AuthenticatorId, AuthenticatorPurpose, ChainId, CryptoSuiteId,
        FreezeState, Principal, PrincipalId, PrincipalKind,
    };
    use activechain_wallet_core::{
        FinalizedIdentityKeyProof, FinalizedIdentityKeyVerifier, authenticator_set_root,
    };
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use std::net::TcpListener;

    struct AcceptFinality;
    impl FinalizedIdentityKeyVerifier for AcceptFinality {
        fn verify_finalized_identity_key(&self, _proof: &FinalizedIdentityKeyProof) -> bool {
            true
        }
    }
    fn identity_proof(owner: PrincipalId, key: &SigningKey<MlDsa44>) -> FinalizedIdentityKeyProof {
        let authenticator = AuthenticatorDescriptor::new(
            AuthenticatorId::new(Digest384::new([91; 48])),
            CryptoSuiteId::ML_DSA_44,
            key.verifying_key().encode().as_slice().to_vec(),
            AuthenticatorPurpose::Session,
            1,
            None,
            None,
        )
        .unwrap();
        let identity = Principal::new(
            owner,
            PrincipalKind::Human,
            Digest384::new([31; 48]),
            Digest384::new([32; 48]),
            authenticator_set_root(core::slice::from_ref(&authenticator)).unwrap(),
            0,
            FreezeState::Active,
            Digest384::new([33; 48]),
            1,
            1,
            30,
        )
        .unwrap();
        FinalizedIdentityKeyProof::new(
            identity,
            authenticator,
            Digest384::new([34; 48]),
            30,
            Digest384::new([35; 48]),
        )
    }
    fn genesis_justification(context: ConsensusVoteContext) -> ProposalJustification {
        ProposalJustification::Finalized(
            ConsensusBlockRef::new(
                context.genesis_commitment(),
                context.genesis_commitment(),
                0,
                0,
            )
            .unwrap(),
        )
    }
    fn sign_test_proposal(
        key: &SigningKey<MlDsa44>,
        proposer: PrincipalId,
        context: ConsensusVoteContext,
        height: u64,
        round: u64,
        block_digest: Digest384,
        justification: ProposalJustification,
    ) -> BlockProposal {
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let unsigned = BlockProposal::new(
            proposer,
            context,
            height,
            round,
            block_digest,
            justification.clone(),
            placeholder,
        )
        .unwrap();
        BlockProposal::new(
            proposer,
            context,
            height,
            round,
            block_digest,
            justification,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                key.sign(&unsigned.signing_payload()).encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn sign_genesis_proposal(
        signer: &ValidatorSigner,
        genesis: &ValidatorGenesis,
        height: u64,
        round: u64,
        block_digest: Digest384,
    ) -> BlockProposal {
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        signer
            .sign_proposal(context, height, round, block_digest, genesis_justification(context))
            .unwrap()
    }
    fn signed_message(
        key: &SigningKey<MlDsa44>,
        sender: u16,
        sequence: u64,
        message: ConsensusMessage,
    ) -> AuthenticatedConsensusMessage {
        let digest = message.digest().unwrap();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let unsigned = SignedPeerEnvelope::new(sender, sequence, digest, placeholder).unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        AuthenticatedConsensusMessage::new(
            SignedPeerEnvelope::new(
                sender,
                sequence,
                digest,
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                    .unwrap(),
            )
            .unwrap(),
            message,
        )
        .unwrap()
    }

    struct CountingVoteSigner {
        validator: PrincipalId,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ConsensusVoteSigner for CountingVoteSigner {
        fn validator(&self) -> PrincipalId {
            self.validator
        }

        fn sign_prepared_vote(
            &self,
            _prepared: &PreparedValidatorVote,
        ) -> Result<ValidatorVote, ValidatorEngineError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ValidatorEngineError::Signer)
        }
    }

    fn finalize_single_validator_proof(
        service: &ValidatorService,
        signer: &ValidatorSigner,
        genesis: &ValidatorGenesis,
        height: u64,
        block_digest: Digest384,
        sequence: u64,
    ) -> CertifiedBlock {
        let (proposal_message, vote_message) =
            service.propose_round(signer, height, 0, block_digest, sequence).unwrap();
        let proposal = match proposal_message.message {
            ConsensusMessage::Proposal(proposal) => proposal,
            _ => panic!("expected proposal"),
        };
        let vote = match vote_message.message {
            ConsensusMessage::Vote(vote) => vote,
            _ => panic!("expected vote"),
        };
        let validator_set = genesis.validator_set().unwrap();
        let mut collector = VoteCollector::new(
            proposal,
            genesis.genesis_commitment(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        );
        collector.add_vote(&validator_set, signer.public_key().as_slice(), vote.clone()).unwrap();
        CertifiedBlock::new(
            collector.proposal().clone(),
            collector.finalize(genesis.epoch(), &validator_set).unwrap(),
            vec![vote],
        )
        .unwrap()
    }

    #[test]
    fn wallet_gateway_binds_a_genesis_ledger() {
        let digest = |byte| Digest384::new([byte; 48]);
        let owner = PrincipalId::new(digest(10));
        let definition = NativeAssetDefinition::new(
            ChainId::new(digest(1)),
            b"ACT".to_vec(),
            18,
            1_000,
            150,
            digest(2),
            digest(3),
            digest(4),
        )
        .unwrap();
        let economy = GenesisEconomy::new(
            definition,
            vec![
                GenesisAllocation::new(owner, 700, 100).unwrap(),
                GenesisAllocation::new(owner, 100, 0).unwrap(),
            ],
            100,
        )
        .unwrap();
        let snapshot_path = std::env::temp_dir()
            .join(format!("activechain-wallet-gateway-{}.snapshot", std::process::id()));
        let adapter_snapshot_path = std::env::temp_dir()
            .join(format!("activechain-wallet-adapter-{}.snapshot", std::process::id()));
        let _ = std::fs::remove_file(&snapshot_path);
        let _ = std::fs::remove_file(&adapter_snapshot_path);
        let mut gateway =
            WalletTransactionGateway::from_genesis(&economy, snapshot_path.clone()).unwrap();
        let shared_gateway = Arc::new(Mutex::new(
            WalletTransactionGateway::from_genesis(&economy, adapter_snapshot_path.clone())
                .unwrap(),
        ));
        let finalized_height = Arc::new(AtomicU64::new(1));
        let adapter = ValidatorFaucetSettlementAdapter::new(shared_gateway, finalized_height);
        assert_eq!(
            adapter.settle_authorized(&[0xff], owner, 10, digest(30),),
            Err(FaucetError::InvalidTransition)
        );
        assert_eq!(
            gateway.submit_faucet_authorized_envelope(&[], digest(30), owner, 10, 1,),
            Err(activechain_wallet_core::WalletError::MalformedAuthorization)
        );
        assert_eq!(gateway.owner_cells(owner).unwrap().as_slice().len(), 2);
        assert!(gateway.owner_cells(PrincipalId::new(digest(11))).unwrap().as_slice().is_empty());
        let snapshot = gateway.finalized_cash_snapshot(digest(20), 1).unwrap();
        assert_eq!(snapshot.chain_genesis, digest(20));
        assert_eq!(snapshot.finalized_height, 1);
        assert_eq!(snapshot.cells.as_slice().len(), 2);
        assert!(gateway.finalized_cash_snapshot(Digest384::ZERO, 1).is_err());
        let cash_key = SigningKey::<MlDsa44>::from_seed(&Seed::from([91; 32]));
        let proof = identity_proof(owner, &cash_key);
        gateway.install_finalized_authorization_key(&proof, 0, &AcceptFinality).unwrap();
        let cells = gateway.ledger().cells().as_slice();
        let transfer = CoinTransfer::new(
            owner,
            PrincipalId::new(digest(11)),
            vec![cells[0].id()],
            cells[1].id(),
            10,
            1,
            10,
        )
        .unwrap();
        let request =
            activechain_wallet_core::CashAuthorizationRequestV1::new_with_settlement_reference(
                ChainId::new(digest(1)),
                owner,
                0,
                digest(12),
                10,
                Some(digest(30)),
                transfer,
            )
            .unwrap();
        let grant = activechain_wallet_core::CashSessionGrantV1::new(
            ChainId::new(digest(1)),
            owner,
            digest(12),
            1,
            10,
            100,
        )
        .unwrap();
        let grant_signature = cash_key.sign(&grant.signing_payload().unwrap());
        let authorized_grant = activechain_wallet_core::AuthorizedCashSessionGrantV1::new(
            grant,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, grant_signature.encode().to_vec())
                .unwrap(),
        )
        .unwrap();
        gateway.register_session(&authorized_grant, 1).unwrap();
        let signature = cash_key.sign(&request.signing_payload().unwrap());
        let authorized = activechain_wallet_core::AuthorizedCashTransferV1::new(
            request,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                signature.encode().as_slice().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let envelope = encode_envelope(&authorized).unwrap();
        assert_eq!(
            gateway.submit_faucet_authorized_envelope(
                &envelope,
                digest(31),
                PrincipalId::new(digest(11)),
                10,
                1,
            ),
            Err(activechain_wallet_core::WalletError::PolicyDenied)
        );
        assert_eq!(
            gateway.submit_faucet_authorized_envelope(
                &envelope,
                digest(30),
                PrincipalId::new(digest(12)),
                10,
                1,
            ),
            Err(activechain_wallet_core::WalletError::PolicyDenied)
        );
        assert_eq!(
            gateway.submit_faucet_authorized_envelope(
                &envelope,
                digest(30),
                PrincipalId::new(digest(11)),
                11,
                1,
            ),
            Err(activechain_wallet_core::WalletError::PolicyDenied)
        );
        assert_eq!(
            gateway.submit_faucet_authorized_envelope(
                &envelope,
                digest(30),
                PrincipalId::new(digest(11)),
                10,
                11,
            ),
            Err(activechain_wallet_core::WalletError::PolicyDenied)
        );
        let pre_ledger = gateway.ledger().clone();
        assert!(gateway.prepare_envelope_batch(&[envelope.clone(), envelope.clone()], 1).is_err());
        assert_eq!(gateway.ledger(), &pre_ledger, "rejected batch must not mutate live state");
        let prepared = gateway.prepare_envelope_batch(&[envelope.clone()], 1).unwrap();
        let stale_prepared = gateway.prepare_envelope_batch(&[envelope.clone()], 1).unwrap();
        assert_eq!(prepared.action_ids().len(), 1);
        assert_ne!(prepared.pre_cash_cell_root(), prepared.post_cash_cell_root());
        assert_ne!(prepared.ledger(), &pre_ledger);
        assert_eq!(gateway.ledger(), &pre_ledger, "prepared state remains unpublished");
        gateway.commit_prepared(prepared).unwrap();
        assert_eq!(
            gateway.commit_prepared(stale_prepared),
            Err(activechain_wallet_core::WalletError::Persistence)
        );
        let retried = gateway.prepare_envelope_batch(&[envelope], 2).unwrap();
        assert_eq!(retried.ledger(), gateway.ledger(), "certified retry is idempotent");
        assert!(retried.action_ids().is_empty());
        assert_eq!(retried.pre_cash_cell_root(), retried.post_cash_cell_root());
        let restored =
            WalletTransactionGateway::load_snapshot(&snapshot_path, ChainId::new(digest(1)))
                .unwrap();
        assert_eq!(restored.ledger(), gateway.ledger());
        std::fs::remove_file(snapshot_path).unwrap();
        let _ = std::fs::remove_file(adapter_snapshot_path);
    }
    #[test]
    fn runtime_rejects_without_verified_votes() {
        let mut state = ConsensusState::new(1);
        let set = ValidatorSet::new(Vec::new());
        assert!(set.is_err());
        let _ = &mut state;
    }

    #[test]
    fn loopback_socket_round_trip_and_replay_guard() {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::default());
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let unsigned = SignedPeerEnvelope::new(4, 1, Digest384::new([9; 48]), placeholder).unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        let envelope = SignedPeerEnvelope::new(
            4,
            1,
            Digest384::new([9; 48]),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut socket = PeerSocket::connect(std::net::TcpStream::connect(address).unwrap());
            socket.send(&envelope).unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let mut socket = PeerSocket::connect(stream);
        let received = socket.receive_envelope().unwrap();
        let mut guard = ReplayGuard::default();
        assert!(guard.accept(&received, key.verifying_key().encode().as_slice()).is_ok());
        assert_eq!(
            guard.accept(&received, key.verifying_key().encode().as_slice()),
            Err(TransportError::Replay)
        );
        sender.join().unwrap();
    }

    #[test]
    fn authenticated_consensus_body_round_trips_and_verifies() {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([7; 32]));
        let vote = ValidatorVote::new(
            activechain_protocol_types::PrincipalId::new(Digest384::new([3; 48])),
            ConsensusVoteContext::new(Digest384::new([10; 48]), 1, Digest384::new([11; 48]))
                .unwrap(),
            8,
            2,
            Digest384::new([4; 48]),
            Digest384::new([5; 48]),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![5; 2420]).unwrap(),
        )
        .unwrap();
        let authenticated = signed_message(&key, 7, 9, ConsensusMessage::Vote(vote.clone()));
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut socket = PeerSocket::connect(std::net::TcpStream::connect(address).unwrap());
            socket.send_message(&authenticated).unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let mut socket = PeerSocket::connect(stream);
        let received = socket.receive_message().unwrap();
        received.envelope.verify(key.verifying_key().encode().as_slice()).unwrap();
        assert_eq!(received.message, ConsensusMessage::Vote(vote));
        sender.join().unwrap();
    }

    #[test]
    fn authenticated_consensus_body_rejects_digest_substitution() {
        let signature = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let vote = ValidatorVote::new(
            activechain_protocol_types::PrincipalId::new(Digest384::new([1; 48])),
            ConsensusVoteContext::new(Digest384::new([10; 48]), 1, Digest384::new([11; 48]))
                .unwrap(),
            1,
            1,
            Digest384::new([2; 48]),
            Digest384::new([3; 48]),
            signature.clone(),
        )
        .unwrap();
        let envelope = SignedPeerEnvelope::new(1, 1, Digest384::new([9; 48]), signature).unwrap();
        assert_eq!(
            AuthenticatedConsensusMessage::new(envelope, ConsensusMessage::Vote(vote)),
            Err(TransportError::BodyDigestMismatch)
        );
    }

    #[test]
    fn peer_socket_rejects_oversized_frame_before_allocation() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream.write_all(&((MAX_PEER_FRAME_LEN as u32) + 1).to_be_bytes()).unwrap();
        });
        let (stream, _) = listener.accept().unwrap();
        let error = PeerSocket::connect(stream).receive_frame().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        sender.join().unwrap();
    }

    fn wait_until(mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !predicate() {
            assert!(Instant::now() < deadline, "condition did not become true");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn peer_frame_deadline_rejects_slow_byte_drip() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            for byte in 4_u32.to_be_bytes() {
                if stream.write_all(&[byte]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });
        let (stream, _) = listener.accept().unwrap();
        let started = Instant::now();
        let error = PeerSocket::connect(stream)
            .receive_frame_until(Instant::now() + Duration::from_millis(70))
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        sender.join().unwrap();
    }

    #[test]
    fn bounded_peer_ingress_sheds_saturation_and_recovers_for_healthy_peer() {
        let listener = PeerListener::bind_with_config(
            ("127.0.0.1", 0),
            PeerIngressConfig {
                workers: 1,
                queue_capacity: 1,
                pre_auth_per_source_per_second: 64,
                max_tracked_sources: 4,
            },
        )
        .unwrap();
        let address = listener.local_addr().unwrap();
        let monitor = listener.monitor();
        let (release_sender, release_receiver) = mpsc::channel();
        let release_receiver = Arc::new(Mutex::new(release_receiver));
        std::thread::spawn(move || {
            listener
                .spawn_accept_loop(move |_| {
                    let _ = release_receiver.lock().unwrap().recv();
                })
                .unwrap();
        });

        let first = TcpStream::connect(address).unwrap();
        wait_until(|| monitor.snapshot().active == 1);
        let second = TcpStream::connect(address).unwrap();
        wait_until(|| monitor.snapshot().queued == 1);
        let shed = TcpStream::connect(address).unwrap();
        wait_until(|| monitor.snapshot().shed == 1);
        drop(shed);

        release_sender.send(()).unwrap();
        release_sender.send(()).unwrap();
        wait_until(|| monitor.snapshot().recovered == 2);
        let healthy = TcpStream::connect(address).unwrap();
        release_sender.send(()).unwrap();
        wait_until(|| monitor.snapshot().recovered == 3);
        let snapshot = monitor.snapshot();
        assert_eq!(snapshot.active, 0);
        assert_eq!(snapshot.queued, 0);
        assert_eq!(snapshot.shed, 1);
        drop((first, second, healthy));
    }

    #[test]
    fn peer_ingress_pre_auth_limit_uses_observed_source_address() {
        let listener = PeerListener::bind_with_config(
            ("127.0.0.1", 0),
            PeerIngressConfig {
                workers: 1,
                queue_capacity: 2,
                pre_auth_per_source_per_second: 1,
                max_tracked_sources: 1,
            },
        )
        .unwrap();
        let address = listener.local_addr().unwrap();
        let monitor = listener.monitor();
        let (release_sender, release_receiver) = mpsc::channel();
        let release_receiver = Arc::new(Mutex::new(release_receiver));
        std::thread::spawn(move || {
            listener
                .spawn_accept_loop(move |_| {
                    let _ = release_receiver.lock().unwrap().recv();
                })
                .unwrap();
        });
        let first = TcpStream::connect(address).unwrap();
        wait_until(|| monitor.snapshot().active == 1);
        let limited = TcpStream::connect(address).unwrap();
        wait_until(|| monitor.snapshot().pre_auth_rate_limited == 1);
        let snapshot = monitor.snapshot();
        assert_eq!(snapshot.accepted, 2);
        assert_eq!(snapshot.shed, 1);
        std::thread::sleep(Duration::from_millis(1050));
        let recovered_source = TcpStream::connect(address).unwrap();
        wait_until(|| monitor.snapshot().queued == 1);
        release_sender.send(()).unwrap();
        release_sender.send(()).unwrap();
        wait_until(|| monitor.snapshot().recovered == 2);
        assert_eq!(monitor.snapshot().pre_auth_rate_limited, 1);
        drop((first, limited, recovered_source));
    }

    #[test]
    fn peer_ingress_configuration_is_absolutely_bounded() {
        let invalid = [
            PeerIngressConfig { workers: 0, ..PeerIngressConfig::default() },
            PeerIngressConfig {
                workers: MAX_PEER_INGRESS_WORKERS + 1,
                ..PeerIngressConfig::default()
            },
            PeerIngressConfig {
                queue_capacity: MAX_PEER_INGRESS_QUEUE + 1,
                ..PeerIngressConfig::default()
            },
            PeerIngressConfig {
                pre_auth_per_source_per_second: MAX_PRE_AUTH_PER_SOURCE_PER_SECOND + 1,
                ..PeerIngressConfig::default()
            },
            PeerIngressConfig {
                max_tracked_sources: MAX_TRACKED_INGRESS_SOURCES + 1,
                ..PeerIngressConfig::default()
            },
        ];
        for config in invalid {
            assert_eq!(
                PeerListener::bind_with_config(("127.0.0.1", 0), config).err().unwrap().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn authenticated_peer_session_bounds_messages_and_lifetime() {
        assert!(ValidatorService::enforce_session_bounds(Instant::now(), 0).is_ok());
        let message_error =
            ValidatorService::enforce_session_bounds(Instant::now(), MAX_PEER_SESSION_MESSAGES)
                .unwrap_err();
        assert_eq!(message_error.kind(), std::io::ErrorKind::InvalidData);
        let lifetime_error =
            ValidatorService::enforce_session_bounds(Instant::now() - PEER_SESSION_LIFETIME, 0)
                .unwrap_err();
        assert_eq!(lifetime_error.kind(), std::io::ErrorKind::TimedOut);

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let mut socket = PeerSocket::connect(stream);
        for _ in 0..MAX_PEER_SESSION_MESSAGES {
            socket.record_session_message();
        }
        assert_eq!(
            socket.ensure_session_message_capacity().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        drop(client);
    }

    #[test]
    fn consensus_dispatch_preserves_peer_identity_and_sequence() {
        let queue = PeerEventQueue::new();
        let envelope = SignedPeerEnvelope::new(
            12,
            42,
            Digest384::new([1; 48]),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap(),
        )
        .unwrap();
        queue.push(PeerEvent { peer_id: 12, envelope }).unwrap();
        let result = ConsensusDispatcher::dispatch_once(&queue, |event| {
            assert_eq!(event.peer_id, 12);
            assert_eq!(event.envelope.sequence(), 42);
            Ok(())
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn bare_pq_qc_verification_never_advances_finality() {
        use activechain_protocol_types::{ValidatorSet, ValidatorWeight};
        let keys: Vec<_> = (0..3)
            .map(|seed_byte| {
                ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&ml_dsa::Seed::from(
                    [seed_byte; 32],
                ))
            })
            .collect();
        let ids: Vec<_> = (0..3)
            .map(|byte| {
                activechain_protocol_types::PrincipalId::new(Digest384::new([byte + 1; 48]))
            })
            .collect();
        let set = ValidatorSet::new(vec![
            ValidatorWeight { validator: ids[0], stake: 4 },
            ValidatorWeight { validator: ids[1], stake: 3 },
            ValidatorWeight { validator: ids[2], stake: 3 },
        ])
        .unwrap();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let genesis_commitment = Digest384::new([50; 48]);
        let validator_set_root = Digest384::new([51; 48]);
        let vote_context =
            ConsensusVoteContext::new(genesis_commitment, 1, validator_set_root).unwrap();
        let proposal = BlockProposal::new(
            ids[0],
            vote_context,
            1,
            0,
            Digest384::new([5; 48]),
            genesis_justification(vote_context),
            placeholder.clone(),
        )
        .unwrap();
        let proposal_commitment = proposal.commitment();
        let mut collector = VoteCollector::new(proposal, genesis_commitment, validator_set_root, 1);
        let mut votes = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            let unsigned = ValidatorVote::new(
                ids[index],
                vote_context,
                1,
                0,
                Digest384::new([5; 48]),
                proposal_commitment,
                placeholder.clone(),
            )
            .unwrap();
            let signature = key.sign(&unsigned.signing_payload());
            let vote = ValidatorVote::new(
                ids[index],
                vote_context,
                1,
                0,
                Digest384::new([5; 48]),
                proposal_commitment,
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                    .unwrap(),
            )
            .unwrap();
            collector
                .add_vote(&set, key.verifying_key().encode().as_slice(), vote.clone())
                .unwrap();
            votes.push((key.verifying_key().encode().to_vec(), vote));
        }
        let certificate = collector.finalize(1, &set).unwrap();
        let vote_refs: Vec<(&[u8], ValidatorVote)> =
            votes.iter().map(|(key, vote)| (key.as_slice(), vote.clone())).collect();
        for _ in 0..3 {
            let state =
                ConsensusState::new_with_consensus_context(1, validator_set_root, 1).unwrap();
            verify_bare_qc_evidence(&state, &set, &certificate, &vote_refs).unwrap();
            assert_eq!(state.finalized_height(), 0);
            assert_eq!(state.finalized_block_digest(), Digest384::ZERO);
        }
    }

    #[test]
    fn validator_engines_complete_proposal_vote_certificate_and_restart() {
        use activechain_protocol_types::{PrincipalId, ValidatorWeight};
        let keys: Vec<_> =
            (0..3).map(|seed| SigningKey::<MlDsa44>::from_seed(&Seed::from([seed; 32]))).collect();
        let ids: Vec<_> =
            (0..3).map(|value| PrincipalId::new(Digest384::new([value + 1; 48]))).collect();
        let set = ValidatorSet::new(
            ids.iter().copied().map(|validator| ValidatorWeight { validator, stake: 1 }).collect(),
        )
        .unwrap();
        let public_keys: BTreeMap<_, _> = ids
            .iter()
            .copied()
            .zip(keys.iter().map(|key| key.verifying_key().encode().to_vec()))
            .collect();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let genesis_commitment = Digest384::new([50; 48]);
        let validator_set_root = Digest384::new([51; 48]);
        let vote_context =
            ConsensusVoteContext::new(genesis_commitment, 1, validator_set_root).unwrap();
        let proposal = sign_test_proposal(
            &keys[0],
            ids[0],
            vote_context,
            1,
            0,
            Digest384::new([8; 48]),
            genesis_justification(vote_context),
        );
        let proposal_commitment = proposal.commitment();
        let mut leader = ValidatorEngine::new(
            ConsensusState::new_with_validator_set_root(1, validator_set_root),
            genesis_commitment,
            set.clone(),
            public_keys.clone(),
        )
        .unwrap();
        leader.process(ConsensusMessage::Proposal(proposal)).unwrap();
        let mut proof = None;
        for (key, id) in keys.iter().zip(ids.iter()) {
            let unsigned = ValidatorVote::new(
                *id,
                vote_context,
                1,
                0,
                Digest384::new([8; 48]),
                proposal_commitment,
                placeholder.clone(),
            )
            .unwrap();
            let vote = ValidatorVote::new(
                *id,
                vote_context,
                1,
                0,
                Digest384::new([8; 48]),
                proposal_commitment,
                ProtocolSignature::new(
                    CryptoSuiteId::ML_DSA_44,
                    key.sign(&unsigned.signing_payload()).encode().to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
            proof = leader.process(ConsensusMessage::Vote(vote)).unwrap().or(proof);
        }
        let proof = proof.unwrap();
        assert_eq!(leader.state().finalized_height(), 0);
        let wire_message = ConsensusMessage::Certificate(proof.clone());
        assert_eq!(
            ConsensusMessage::decode(3, &wire_message.encode_body().unwrap()).unwrap(),
            wire_message
        );
        let mut follower = ValidatorEngine::new(
            ConsensusState::new_with_validator_set_root(1, validator_set_root),
            genesis_commitment,
            set,
            public_keys,
        )
        .unwrap();
        follower.process(ConsensusMessage::Certificate(proof)).unwrap();
        assert_eq!(follower.state().finalized_height(), 0);
    }

    #[test]
    fn distinct_proposal_histories_cannot_alias_certificates() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let first =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([115; 48])), [116; 32]);
        let second =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([117; 48])), [118; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    first.validator(),
                    3,
                    first.public_key().try_into().unwrap(),
                )
                .unwrap(),
                ValidatorGenesisEntry::new(
                    second.validator(),
                    1,
                    second.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let payload_digest = Digest384::new([119; 48]);
        let proposal_a = first
            .sign_proposal(context, 1, 0, payload_digest, genesis_justification(context))
            .unwrap();
        let proposal_b = first
            .sign_proposal(context, 1, 0, Digest384::new([120; 48]), genesis_justification(context))
            .unwrap();
        let proposal_b_for_substitution = proposal_b.clone();
        assert_ne!(proposal_a.block_digest(), proposal_b.block_digest());
        assert_ne!(proposal_a.commitment(), proposal_b.commitment());

        let state = ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root());
        let mut node_a = ValidatorEngine::from_genesis(state, &genesis).unwrap();
        node_a.process(ConsensusMessage::Proposal(proposal_a)).unwrap();
        let vote_a = node_a.sign_current_vote(&first).unwrap();
        let proof_a = node_a.process(ConsensusMessage::Vote(vote_a)).unwrap().unwrap();
        assert_eq!(
            CertifiedBlock::new(
                proposal_b_for_substitution,
                proof_a.certificate().clone(),
                proof_a.votes().to_vec(),
            ),
            Err(TransportError::InvalidBody)
        );

        let mut node_b = ValidatorEngine::from_genesis(state, &genesis).unwrap();
        node_b.process(ConsensusMessage::Proposal(proposal_b)).unwrap();
        let vote_b = node_b.sign_current_vote(&first).unwrap();
        let proof_b = node_b.process(ConsensusMessage::Vote(vote_b)).unwrap().unwrap();
        assert_ne!(proof_a.certificate().block_digest(), proof_b.certificate().block_digest());
        assert_ne!(
            proof_a.certificate().proposal_commitment(),
            proof_b.certificate().proposal_commitment()
        );

        let child_of_b = second
            .sign_proposal(
                context,
                2,
                1,
                Digest384::new([120; 48]),
                ProposalJustification::Quorum(proof_b.certificate().clone()),
            )
            .unwrap();
        assert!(matches!(
            node_a.process(ConsensusMessage::Proposal(child_of_b)),
            Err(ValidatorEngineError::UnknownParentCertificate)
        ));
        assert!(node_a.certified_blocks.contains_key(&proof_a.certificate().proposal_commitment()));
        assert!(
            !node_a.certified_blocks.contains_key(&proof_b.certificate().proposal_commitment())
        );

        let child_of_a = second
            .sign_proposal(
                context,
                2,
                1,
                Digest384::new([120; 48]),
                ProposalJustification::Quorum(proof_a.certificate().clone()),
            )
            .unwrap();
        node_a.process(ConsensusMessage::Proposal(child_of_a)).unwrap();
        node_a.sign_current_vote(&first).unwrap();
        assert_eq!(
            node_a.locked_qc.as_ref().map(QuorumCertificate::proposal_commitment),
            Some(proof_a.certificate().proposal_commitment())
        );
        assert!(matches!(
            second.sign_proposal(
                context,
                1,
                2,
                Digest384::new([121; 48]),
                genesis_justification(context),
            ),
            Err(ValidatorEngineError::Signer)
        ));
    }

    #[test]
    fn competing_proposal_does_not_discard_accumulated_quorum_votes() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let signers = [
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([201; 48])), [202; 32]),
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([203; 48])), [204; 32]),
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([205; 48])), [206; 32]),
        ];
        let mut entries: Vec<_> = signers
            .iter()
            .map(|signer| {
                ValidatorGenesisEntry::new(
                    signer.validator(),
                    1,
                    signer.public_key().try_into().unwrap(),
                )
                .unwrap()
            })
            .collect();
        entries.sort_by_key(ValidatorGenesisEntry::validator);
        let genesis = ValidatorGenesis::new(1, 1, entries).unwrap();
        let context = ConsensusVoteContext::new(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
        )
        .unwrap();
        let proposal_a = signers[0]
            .sign_proposal(context, 1, 0, Digest384::new([207; 48]), genesis_justification(context))
            .unwrap();
        let proposal_b = signers[0]
            .sign_proposal(context, 1, 0, Digest384::new([208; 48]), genesis_justification(context))
            .unwrap();
        let commitment_a = proposal_a.commitment();
        let commitment_b = proposal_b.commitment();
        let mut engine = ValidatorEngine::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
        )
        .unwrap();
        engine.process(ConsensusMessage::Proposal(proposal_a.clone())).unwrap();
        assert!(
            engine
                .process(ConsensusMessage::Vote(
                    signers[0]
                        .sign_vote(
                            &proposal_a,
                            genesis.genesis_commitment(),
                            genesis.validator_set_root(),
                            genesis.protocol_revision(),
                        )
                        .unwrap(),
                ))
                .unwrap()
                .is_none()
        );
        engine.process(ConsensusMessage::Proposal(proposal_b)).unwrap();
        assert!(engine.collectors.contains_key(&commitment_a));
        assert!(engine.collectors.contains_key(&commitment_b));
        assert!(
            engine
                .process(ConsensusMessage::Vote(
                    signers[1]
                        .sign_vote(
                            &proposal_a,
                            genesis.genesis_commitment(),
                            genesis.validator_set_root(),
                            genesis.protocol_revision(),
                        )
                        .unwrap(),
                ))
                .unwrap()
                .is_none()
        );
        let proof = engine
            .process(ConsensusMessage::Vote(
                signers[2]
                    .sign_vote(
                        &proposal_a,
                        genesis.genesis_commitment(),
                        genesis.validator_set_root(),
                        genesis.protocol_revision(),
                    )
                    .unwrap(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(proof.certificate().proposal_commitment(), commitment_a);
        assert!(!engine.collectors.contains_key(&commitment_a));
        assert!(engine.collectors.contains_key(&commitment_b));
    }

    #[test]
    fn same_slot_different_proposal_is_rejected_after_restart() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let first =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([121; 48])), [122; 32]);
        let second =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([123; 48])), [124; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    first.validator(),
                    3,
                    first.public_key().try_into().unwrap(),
                )
                .unwrap(),
                ValidatorGenesisEntry::new(
                    second.validator(),
                    1,
                    second.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new(
            genesis.genesis_commitment(),
            1,
            genesis.validator_set_root(),
        )
        .unwrap();
        let payload = Digest384::new([125; 48]);
        let proposal_a =
            first.sign_proposal(context, 1, 0, payload, genesis_justification(context)).unwrap();
        let proposal_a_commitment = proposal_a.commitment();
        let proposal_b = first
            .sign_proposal(context, 1, 0, Digest384::new([126; 48]), genesis_justification(context))
            .unwrap();
        assert_ne!(proposal_a_commitment, proposal_b.commitment());
        let path = std::env::temp_dir()
            .join(format!("activechain-proposal-identity-restart-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        service
            .process_proposal_and_sign_vote(
                first.sign_envelope(1, 1, ConsensusMessage::Proposal(proposal_a.clone())).unwrap(),
                &first,
                2,
            )
            .unwrap();
        drop(service);

        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        assert!(matches!(
            restarted.process_proposal_and_sign_vote(
                first.sign_envelope(1, 4, ConsensusMessage::Proposal(proposal_b)).unwrap(),
                &first,
                5,
            ),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::ConflictingLocalVote))
        ));
        let repeated = restarted
            .process_proposal_and_sign_vote(
                first.sign_envelope(1, 6, ConsensusMessage::Proposal(proposal_a)).unwrap(),
                &first,
                7,
            )
            .unwrap();
        assert!(matches!(
            repeated.message,
            ConsensusMessage::Vote(ref vote)
                if vote.proposal_commitment() == proposal_a_commitment
        ));
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn validator_engine_rejects_genesis_epoch_mismatch() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let genesis = ValidatorGenesis::new(
            9,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    activechain_protocol_types::PrincipalId::new(Digest384::new([1; 48])),
                    1,
                    [2; activechain_protocol_types::ML_DSA44_PUBLIC_KEY_LENGTH],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert!(matches!(
            ValidatorEngine::from_genesis(ConsensusState::new(8), &genesis),
            Err(ValidatorEngineError::GenesisEpochMismatch)
        ));
    }

    #[test]
    fn validator_signer_produces_a_provider_verifiable_vote() {
        use activechain_protocol_types::{PrincipalId, ValidatorWeight};
        let validator = PrincipalId::new(Digest384::new([4; 48]));
        let signer = ValidatorSigner::from_seed(validator, [6; 32]);
        let set = ValidatorSet::new(vec![ValidatorWeight { validator, stake: 1 }]).unwrap();
        let mut keys = BTreeMap::new();
        keys.insert(validator, signer.public_key());
        let context =
            ConsensusVoteContext::new(Digest384::new([50; 48]), 1, Digest384::new([51; 48]))
                .unwrap();
        let proposal = sign_test_proposal(
            &signer.key,
            validator,
            context,
            1,
            0,
            Digest384::new([5; 48]),
            genesis_justification(context),
        );
        let mut engine = ValidatorEngine::new(
            ConsensusState::new_with_validator_set_root(1, Digest384::new([51; 48])),
            Digest384::new([50; 48]),
            set,
            keys,
        )
        .unwrap();
        engine.process(ConsensusMessage::Proposal(proposal.clone())).unwrap();
        let vote = engine.sign_current_vote(&signer).unwrap();
        activechain_crypto_provider::verify_validator_vote(&signer.public_key(), &vote).unwrap();
        assert!(engine.process(ConsensusMessage::Vote(vote)).unwrap().is_some());
    }

    #[test]
    fn persistent_service_drives_single_validator_round_to_finality() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = activechain_protocol_types::PrincipalId::new(Digest384::new([6; 48]));
        let signer = ValidatorSigner::from_seed(validator, [7; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("activechain-round-{}.bin", std::process::id()));
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        service.propose_round(&signer, 1, 0, Digest384::new([8; 48]), 1).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 0);
        service.propose_round(&signer, 2, 1, Digest384::new([9; 48]), 3).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 1);
        let metrics = service.metrics();
        assert_eq!(metrics.proposals, 2);
        assert_eq!(metrics.votes, 2);
        assert_eq!(metrics.finalized_certificates, 1);
        assert_eq!(metrics.rejected_messages, 0);
        assert!(
            metrics
                .prometheus(1)
                .contains("activechain_validator_finalized_certificates{validator=\"1\"} 1")
        );
        let rate_window = Instant::now();
        for _ in 0..MAX_AUTHENTICATED_MESSAGES_PER_SECOND {
            assert!(service.allow_authenticated_receive(1, rate_window).unwrap());
        }
        assert!(!service.allow_authenticated_receive(1, rate_window).unwrap());
        assert_eq!(service.metrics().peer_rate_limited, 1);
        service.record_peer_io_error(&std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "test timeout",
        ));
        service.record_peer_io_error(&invalid_data("test malformed frame"));
        let ingress_metrics = service.metrics();
        assert_eq!(ingress_metrics.peer_timeouts, 1);
        assert_eq!(ingress_metrics.peer_malformed_frames, 1);
        let rendered = ingress_metrics.prometheus(1);
        assert!(rendered.contains("activechain_validator_peer_timeouts{validator=\"1\"} 1"));
        assert!(
            rendered.contains("activechain_validator_peer_malformed_frames{validator=\"1\"} 1")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn outbound_sequence_and_first_qc_ancestry_survive_restart() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([91; 48]));
        let signer = ValidatorSigner::from_seed(validator, [92; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-outbound-restart-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        assert_eq!(service.next_sequence(1).unwrap(), 1);
        service.propose_round(&signer, 1, 0, Digest384::new([93; 48]), 1).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 0);
        assert_eq!(service.next_sequence(1).unwrap(), 3);
        drop(service);

        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        assert_eq!(restarted.next_sequence(1).unwrap(), 3);
        assert_eq!(restarted.next_proposal_position().unwrap(), (2, 1));
        restarted.propose_round(&signer, 2, 1, Digest384::new([94; 48]), 3).unwrap();
        assert_eq!(restarted.state().unwrap().finalized_height(), 1);
        assert_eq!(restarted.next_sequence(1).unwrap(), 5);
        assert!(matches!(
            restarted.reserve_sequence_range(1, 3, 1),
            Err(ValidatorServiceError::Transport(TransportError::Replay))
        ));
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn snapshot_failure_prevents_any_vote_signer_invocation() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([95; 48]));
        let signer = ValidatorSigner::from_seed(validator, [96; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let directory =
            std::env::temp_dir().join(format!("activechain-sign-boundary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("validator.snapshot");
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        let proposal = sign_genesis_proposal(&signer, &genesis, 1, 0, Digest384::new([97; 48]));
        service
            .process_message(
                signer.sign_envelope(1, 1, ConsensusMessage::Proposal(proposal)).unwrap(),
            )
            .unwrap();
        let before = service.engine.lock().unwrap().clone();
        assert!(before.local_vote_locks.is_empty());
        assert!(before.locked_qc.is_none());

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let spy = CountingVoteSigner { validator, calls: std::sync::Arc::clone(&calls) };
        assert!(matches!(
            service.sign_current_vote_durably(&spy),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::Snapshot(_)))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let after = service.engine.lock().unwrap();
        assert_eq!(after.local_vote_locks, before.local_vote_locks);
        assert_eq!(after.highest_voted_rounds, before.highest_voted_rounds);
        assert_eq!(after.locked_qc, before.locked_qc);
        assert_eq!(after.active_anchor, before.active_anchor);
        assert_eq!(after.certified_blocks, before.certified_blocks);
        assert!(!after.collectors.is_empty());
    }

    #[test]
    fn outbound_sequence_overflow_survives_restart_and_fails_closed() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([98; 48]));
        let signer = ValidatorSigner::from_seed(validator, [99; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-sequence-overflow-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        {
            let engine = service.engine.lock().unwrap();
            let replay = service.replay.lock().unwrap();
            let mut outbound = service.outbound_high_water.lock().unwrap();
            outbound.insert(1, u64::MAX);
            save_validator_snapshot(&path, &engine, &replay, &outbound).unwrap();
        }
        drop(service);

        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        assert!(matches!(
            restarted.next_sequence(1),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))
        ));
        let before = restarted.engine.lock().unwrap().clone();
        assert!(matches!(
            restarted.propose_round(&signer, 1, 0, Digest384::new([100; 48]), u64::MAX),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))
        ));
        let after = restarted.engine.lock().unwrap();
        assert_eq!(after.state, before.state);
        assert_eq!(after.local_vote_locks, before.local_vote_locks);
        assert_eq!(after.certified_blocks, before.certified_blocks);
        drop(after);
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn restored_genesis_anchor_rejects_canonical_semantic_tampering() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([134; 48]));
        let signer = ValidatorSigner::from_seed(validator, [135; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let state = ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root());
        let base_path = std::env::temp_dir()
            .join(format!("activechain-anchor-base-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&base_path);
        let service = ValidatorService::from_genesis(state, &genesis, base_path.clone()).unwrap();
        service.reserve_sequence_range(1, 1, 1).unwrap();
        drop(service);
        let bytes = std::fs::read(&base_path).unwrap();
        let base: PersistedValidatorState = decode_envelope(&bytes).unwrap();
        let genesis_commitment = genesis.genesis_commitment();
        let tampered_anchors = [
            ConsensusBlockRef::new(Digest384::new([136; 48]), genesis_commitment, 0, 0).unwrap(),
            ConsensusBlockRef::new(genesis_commitment, Digest384::new([137; 48]), 0, 0).unwrap(),
            ConsensusBlockRef::new(genesis_commitment, genesis_commitment, 1, 0).unwrap(),
            ConsensusBlockRef::new(genesis_commitment, genesis_commitment, 0, 1).unwrap(),
        ];
        for (index, anchor) in tampered_anchors.into_iter().enumerate() {
            let mut tampered = base.clone();
            tampered.active_anchor = anchor;
            let path = std::env::temp_dir()
                .join(format!("activechain-anchor-tampered-{}-{index}.bin", std::process::id()));
            let _ = std::fs::remove_file(&path);
            write_atomic(&path, &encode_envelope(&tampered).unwrap()).unwrap();
            assert!(matches!(
                ValidatorService::from_genesis(state, &genesis, path.clone()),
                Err(ValidatorEngineError::InvalidSafetySnapshot)
            ));
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_file(base_path).unwrap();
    }

    #[test]
    fn complete_engine_snapshot_restores_first_qc_before_finality() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([101; 48]));
        let signer = ValidatorSigner::from_seed(validator, [102; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-engine-first-qc-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        service.propose_round(&signer, 1, 0, Digest384::new([103; 48]), 1).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 0);
        assert_eq!(service.engine.lock().unwrap().certified_blocks.len(), 1);
        drop(service);

        let restored = load_snapshot(&path).unwrap();
        let service = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 0);
        let engine = service.engine.lock().unwrap();
        assert_eq!(engine.certified_blocks.len(), 1);
        let record = engine.certified_blocks.values().next().unwrap();
        assert_eq!(record.proposal.commitment(), record.certificate.proposal_commitment());
        assert_eq!(record.votes.len(), 1);
        assert_eq!(record.votes[0].proposal_commitment(), record.proposal.commitment());
        drop(engine);
        assert_eq!(service.next_proposal_position().unwrap(), (2, 1));
        drop(service);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn schema_four_migration_is_bounded_by_available_certified_history() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([149; 48]));
        let signer = ValidatorSigner::from_seed(validator, [150; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let state = ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root());
        let path = std::env::temp_dir()
            .join(format!("activechain-schema-four-migration-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let service = ValidatorService::from_genesis(state, &genesis, path.clone()).unwrap();
        service.reserve_sequence_range(1, 1, 1).unwrap();
        drop(service);
        let mut empty_history_v4 = std::fs::read(&path).unwrap();
        empty_history_v4.truncate(empty_history_v4.len() - 2);
        empty_history_v4[2..4].copy_from_slice(&4_u16.to_be_bytes());
        write_atomic(&path, &empty_history_v4).unwrap();
        let migrated = ValidatorService::from_genesis(state, &genesis, path.clone()).unwrap();
        drop(migrated);
        assert_eq!(&std::fs::read(&path).unwrap()[2..4], &6_u16.to_be_bytes());

        let mut missing_history_v4 = empty_history_v4;
        missing_history_v4.truncate(missing_history_v4.len() - 1);
        write_atomic(&path, &missing_history_v4).unwrap();
        assert!(matches!(
            ValidatorService::from_genesis(state, &genesis, path.clone()),
            Err(ValidatorEngineError::Snapshot(error)) if error.kind() == std::io::ErrorKind::InvalidData
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn authenticated_history_response_survives_restart_and_rejects_replay_and_gaps() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([152; 48]));
        let signer = ValidatorSigner::from_seed(validator, [153; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let state = ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root());
        let producer_path = std::env::temp_dir()
            .join(format!("activechain-history-producer-{}.bin", std::process::id()));
        let requester_path = std::env::temp_dir()
            .join(format!("activechain-history-requester-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&producer_path);
        let _ = std::fs::remove_file(&requester_path);
        let producer =
            ValidatorService::from_genesis(state, &genesis, producer_path.clone()).unwrap();
        let requester =
            ValidatorService::from_genesis(state, &genesis, requester_path.clone()).unwrap();
        let (_, vote) =
            producer.propose_round(&signer, 1, 0, Digest384::new([154; 48]), 1).unwrap();
        let commitment = match vote.message {
            ConsensusMessage::Vote(vote) => vote.proposal_commitment(),
            _ => panic!("expected vote"),
        };

        let request = requester.request_certified_block(&signer, commitment, 3).unwrap();
        let response = producer
            .process_certified_block_request_and_sign_response(request, &signer, 4)
            .unwrap();
        requester.process_message(response.clone()).unwrap();
        assert!(requester.engine.lock().unwrap().certified_blocks.contains_key(&commitment));

        let malformed = AuthenticatedConsensusMessage::new(
            response.envelope.clone(),
            ConsensusMessage::CertifiedBlockRequest(commitment),
        );
        assert_eq!(malformed, Err(TransportError::BodyDigestMismatch));
        drop(requester);
        let restored = load_snapshot(&requester_path).unwrap();
        let restarted =
            ValidatorService::from_genesis(restored, &genesis, requester_path.clone()).unwrap();
        assert!(restarted.engine.lock().unwrap().certified_blocks.contains_key(&commitment));
        assert!(matches!(
            restarted.process_message(response),
            Err(ValidatorServiceError::Transport(TransportError::Replay))
        ));

        let missing =
            restarted.request_certified_block(&signer, Digest384::new([155; 48]), 5).unwrap();
        assert!(matches!(
            producer.process_certified_block_request_and_sign_response(missing, &signer, 6),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::MissingCertifiedHistory))
        ));
        drop(restarted);
        drop(producer);
        std::fs::remove_file(producer_path).unwrap();
        std::fs::remove_file(requester_path).unwrap();
    }

    #[test]
    fn certified_ancestry_bound_exhaustion_never_evicts_safety_history() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([104; 48]));
        let signer = ValidatorSigner::from_seed(validator, [105; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let mut engine = ValidatorEngine::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
        )
        .unwrap();
        let real_digest = Digest384::new([106; 48]);
        let proposal = sign_genesis_proposal(&signer, &genesis, 1, 0, real_digest);
        let real_proposal_commitment = proposal.commitment();
        engine.process(ConsensusMessage::Proposal(proposal.clone())).unwrap();
        let vote = engine.sign_current_vote(&signer).unwrap();
        let parent = ConsensusBlockRef::new(
            genesis.genesis_commitment(),
            genesis.genesis_commitment(),
            0,
            0,
        )
        .unwrap();
        for index in 0..MAX_PERSISTED_CERTIFIED_BLOCKS {
            let mut block = [107_u8; 48];
            block[40..].copy_from_slice(&(index as u64).to_be_bytes());
            let mut root = [108_u8; 48];
            root[40..].copy_from_slice(&(index as u64).to_be_bytes());
            let mut proposal_id = [109_u8; 48];
            proposal_id[40..].copy_from_slice(&(index as u64).to_be_bytes());
            let block_digest = Digest384::new(block);
            let proposal_commitment = Digest384::new(proposal_id);
            let certificate = QuorumCertificate::new(
                context,
                1,
                1,
                block_digest,
                proposal_commitment,
                Digest384::new(root),
                1,
                1,
            )
            .unwrap();
            assert!(
                engine
                    .certified_blocks
                    .insert(
                        proposal_commitment,
                        CertifiedBlockRecord {
                            proposal: proposal.clone(),
                            certificate,
                            votes: Vec::new(),
                            parent,
                        },
                    )
                    .is_none()
            );
        }
        let before_state = engine.state;
        let before_anchor = engine.active_anchor;
        let before_lock = engine.locked_qc.clone();
        let before_keys: Vec<_> = engine.certified_blocks.keys().copied().collect();
        assert!(matches!(
            engine.process(ConsensusMessage::Vote(vote)),
            Err(ValidatorEngineError::CertifiedBlockLimit)
        ));
        assert_eq!(engine.state, before_state);
        assert_eq!(engine.active_anchor, before_anchor);
        assert_eq!(engine.locked_qc, before_lock);
        assert_eq!(engine.certified_blocks.len(), MAX_PERSISTED_CERTIFIED_BLOCKS);
        assert_eq!(engine.certified_blocks.keys().copied().collect::<Vec<_>>(), before_keys);
        assert!(!engine.certified_blocks.contains_key(&real_proposal_commitment));
    }

    #[test]
    fn finalized_ancestry_pruning_progresses_beyond_bound() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([138; 48]));
        let signer = ValidatorSigner::from_seed(validator, [139; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new(
            genesis.genesis_commitment(),
            1,
            genesis.validator_set_root(),
        )
        .unwrap();
        let mut engine = ValidatorEngine::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
        )
        .unwrap();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let total = MAX_PERSISTED_CERTIFIED_BLOCKS + 32;
        let mut previous_qc = None;
        for index in 1..=total {
            let height = index as u64;
            let round = height - 1;
            let mut block = [140_u8; 48];
            block[40..].copy_from_slice(&height.to_be_bytes());
            let justification = previous_qc
                .as_ref()
                .cloned()
                .map(ProposalJustification::Quorum)
                .unwrap_or_else(|| genesis_justification(context));
            let proposal = BlockProposal::new(
                validator,
                context,
                height,
                round,
                Digest384::new(block),
                justification,
                placeholder.clone(),
            )
            .unwrap();
            let mut vote_root = [141_u8; 48];
            vote_root[40..].copy_from_slice(&height.to_be_bytes());
            let certificate = QuorumCertificate::new(
                context,
                height,
                round,
                proposal.block_digest(),
                proposal.commitment(),
                Digest384::new(vote_root),
                1,
                1,
            )
            .unwrap();
            let vote = ValidatorVote::new(
                validator,
                context,
                height,
                round,
                proposal.block_digest(),
                proposal.commitment(),
                placeholder.clone(),
            )
            .unwrap();
            engine.apply_verified_certificate_transition(&proposal, &certificate, &[vote]).unwrap();
            previous_qc = Some(certificate);
            assert!(engine.certified_blocks.len() <= 1);
        }
        assert_eq!(engine.state.finalized_height(), (total - 1) as u64);
        assert_eq!(engine.certified_blocks.len(), 1);
        assert_eq!(
            engine.certified_blocks.keys().next().copied(),
            previous_qc.as_ref().map(QuorumCertificate::proposal_commitment)
        );
    }

    #[test]
    fn restart_restores_replay_high_water_and_conflicting_local_vote_lock() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([61; 48]));
        let signer = ValidatorSigner::from_seed(validator, [62; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-validator-safety-restart-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let state = ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root());
        let service = ValidatorService::from_genesis(state, &genesis, path.clone()).unwrap();
        let first_proposal =
            sign_genesis_proposal(&signer, &genesis, 1, 0, Digest384::new([63; 48]));
        let first_message =
            signer.sign_envelope(1, 7, ConsensusMessage::Proposal(first_proposal)).unwrap();
        service.process_proposal_and_sign_vote(first_message.clone(), &signer, 8).unwrap();
        drop(service);

        let restored_state = load_snapshot(&path).unwrap();
        let restarted =
            ValidatorService::from_genesis(restored_state, &genesis, path.clone()).unwrap();
        assert!(matches!(
            restarted.process_message(first_message),
            Err(ValidatorServiceError::Transport(TransportError::Replay))
        ));

        let same_proposal =
            sign_genesis_proposal(&signer, &genesis, 1, 0, Digest384::new([63; 48]));
        let same_message =
            signer.sign_envelope(1, 9, ConsensusMessage::Proposal(same_proposal)).unwrap();
        let repeated_vote =
            restarted.process_proposal_and_sign_vote(same_message, &signer, 10).unwrap();
        assert!(matches!(
            repeated_vote.message,
            ConsensusMessage::Vote(ref vote) if vote.block_digest() == Digest384::new([63; 48])
        ));

        let conflicting = sign_genesis_proposal(&signer, &genesis, 1, 0, Digest384::new([64; 48]));
        let conflicting_message =
            signer.sign_envelope(1, 11, ConsensusMessage::Proposal(conflicting)).unwrap();
        assert!(matches!(
            restarted.process_proposal_and_sign_vote(conflicting_message, &signer, 12),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::ConflictingLocalVote))
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn unjustified_future_view_is_rejected_before_durable_state() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([126; 48]));
        let signer = ValidatorSigner::from_seed(validator, [127; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let context = ConsensusVoteContext::new(
            genesis.genesis_commitment(),
            1,
            genesis.validator_set_root(),
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-durable-view-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        assert!(matches!(
            signer.sign_proposal(
                context,
                1,
                u64::MAX,
                Digest384::new([128; 48]),
                genesis_justification(context),
            ),
            Err(ValidatorEngineError::Signer)
        ));
        drop(service);
        assert!(!path.exists());
    }

    #[test]
    fn highest_voted_round_survives_finalized_slot_pruning_and_restart() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([130; 48]));
        let signer = ValidatorSigner::from_seed(validator, [131; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-view-pruning-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        service.propose_round(&signer, 1, 0, Digest384::new([132; 48]), 1).unwrap();
        service.propose_round(&signer, 2, 1, Digest384::new([133; 48]), 3).unwrap();
        {
            let engine = service.engine.lock().unwrap();
            assert!(engine.local_vote_locks.keys().all(|slot| slot.height > 1));
            assert_eq!(engine.highest_voted_rounds.len(), 1);
            assert_eq!(engine.highest_voted_rounds.values().next().unwrap().round, 1);
        }
        drop(service);
        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        {
            let engine = restarted.engine.lock().unwrap();
            assert!(engine.local_vote_locks.keys().all(|slot| slot.height > 1));
            assert_eq!(engine.highest_voted_rounds.values().next().unwrap().round, 1);
        }
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn validator_set_activation_requires_prior_qc_and_exact_height() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = activechain_protocol_types::PrincipalId::new(Digest384::new([75; 48]));
        let signer = ValidatorSigner::from_seed(validator, [76; 32]);
        let next_signer = ValidatorSigner::from_seed(validator, [77; 32]);
        let current = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let next = ValidatorGenesis::new(
            2,
            3,
            vec![
                ValidatorGenesisEntry::new(
                    validator,
                    1,
                    next_signer.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("activechain-activation-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, current.validator_set_root()),
            &current,
            path.clone(),
        )
        .unwrap();
        let authorization = ConsensusUpgradeAuthorization::new(
            1,
            3,
            1,
            2,
            current.validator_set_root(),
            next.validator_set_root(),
            1,
            1,
        )
        .unwrap();
        let proof = finalize_single_validator_proof(
            &service,
            &signer,
            &current,
            1,
            authorization.commitment(),
            1,
        );
        service.propose_round(&signer, 2, 1, Digest384::new([79; 48]), 3).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 1);
        {
            let engine = service.engine.lock().unwrap();
            assert_eq!(engine.active_anchor.height(), 1);
            assert!(
                !engine.certified_blocks.contains_key(&proof.certificate().proposal_commitment())
            );
            assert_eq!(engine.certified_blocks.len(), 1);
            let retained_handoff = engine.certified_blocks.values().next().unwrap();
            assert_eq!(retained_handoff.certificate.height(), 2);
            assert_eq!(
                retained_handoff.parent.proposal_commitment(),
                proof.certificate().proposal_commitment()
            );
        }
        drop(service);
        let restored = load_snapshot(&path).unwrap();
        let service = ValidatorService::from_genesis(restored, &current, path.clone()).unwrap();
        {
            let engine = service.engine.lock().unwrap();
            assert_eq!(engine.active_anchor.height(), 1);
            assert!(
                !engine.certified_blocks.contains_key(&proof.certificate().proposal_commitment())
            );
            assert_eq!(engine.certified_blocks.len(), 1);
            assert_eq!(engine.certified_blocks.values().next().unwrap().certificate.height(), 2);
        }

        let wrong_authorization = ConsensusUpgradeAuthorization::new(
            1,
            3,
            1,
            2,
            current.validator_set_root(),
            Digest384::new([99; 48]),
            1,
            1,
        )
        .unwrap();
        assert!(
            service.activate_finalized_validator_set(&wrong_authorization, &proof, &next).is_err()
        );
        service.activate_finalized_validator_set(&authorization, &proof, &next).unwrap();
        assert_eq!(service.state().unwrap().epoch(), 2);
        assert_eq!(service.state().unwrap().validator_set_root(), next.validator_set_root());
        assert_eq!(
            service.state().unwrap().retired_validator_set_roots(),
            &[current.validator_set_root()]
        );
        service.propose_round(&next_signer, 3, 2, Digest384::new([78; 48]), 5).unwrap();
        service.propose_round(&next_signer, 4, 3, Digest384::new([80; 48]), 7).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 3);
        drop(service);
        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_active_manifest(
            restored,
            &next,
            current.genesis_commitment(),
            path.clone(),
        )
        .unwrap();
        assert_eq!(restarted.state().unwrap().epoch(), 2);
        assert_eq!(restarted.state().unwrap().retired_validator_set_roots().len(), 1);
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn protocol_upgrade_rejects_stale_revision_certificates() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([80; 48]));
        let signer = ValidatorSigner::from_seed(validator, [81; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-protocol-upgrade-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let service = ValidatorService::from_genesis(
            ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
            &genesis,
            path.clone(),
        )
        .unwrap();
        let authorization = ConsensusUpgradeAuthorization::new(
            1,
            3,
            1,
            1,
            genesis.validator_set_root(),
            genesis.validator_set_root(),
            1,
            2,
        )
        .unwrap();
        let proof = finalize_single_validator_proof(
            &service,
            &signer,
            &genesis,
            1,
            authorization.commitment(),
            1,
        );
        service.propose_round(&signer, 2, 1, Digest384::new([84; 48]), 3).unwrap();
        service.activate_finalized_protocol_upgrade(&authorization, &proof).unwrap();
        assert_eq!(service.state().unwrap().protocol_revision(), 2);
        assert_eq!(load_snapshot(&path).unwrap().protocol_revision(), 2);

        let stale_context = ConsensusVoteContext::new(
            genesis.genesis_commitment(),
            1,
            genesis.validator_set_root(),
        )
        .unwrap();
        let stale_proposal = signer
            .sign_proposal(
                stale_context,
                2,
                1,
                Digest384::new([82; 48]),
                ProposalJustification::Quorum(proof.certificate().clone()),
            )
            .unwrap();
        let stale_vote = signer
            .sign_vote(
                &stale_proposal,
                genesis.genesis_commitment(),
                genesis.validator_set_root(),
                1,
            )
            .unwrap();
        let validator_set = genesis.validator_set().unwrap();
        let mut collector = VoteCollector::new(
            stale_proposal.clone(),
            genesis.genesis_commitment(),
            genesis.validator_set_root(),
            1,
        );
        collector
            .add_vote(&validator_set, signer.public_key().as_slice(), stale_vote.clone())
            .unwrap();
        let stale_proof = CertifiedBlock::new(
            stale_proposal,
            collector.finalize(1, &validator_set).unwrap(),
            vec![stale_vote],
        )
        .unwrap();
        assert!(matches!(
            service.engine.lock().unwrap().process(ConsensusMessage::Certificate(stale_proof)),
            Err(ValidatorEngineError::VoteDomainMismatch)
        ));

        service.propose_round(&signer, 3, 2, Digest384::new([83; 48]), 5).unwrap();
        service.propose_round(&signer, 4, 3, Digest384::new([85; 48]), 7).unwrap();
        assert_eq!(service.state().unwrap().finalized_height(), 3);
        let active_revision = ValidatorGenesis::new_with_revision(
            1,
            1,
            2,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        drop(service);
        let restored = load_snapshot(&path).unwrap();
        let restarted = ValidatorService::from_active_manifest(
            restored,
            &active_revision,
            genesis.genesis_commitment(),
            path.clone(),
        )
        .unwrap();
        assert_eq!(restarted.state().unwrap().protocol_revision(), 2);
        drop(restarted);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn schema_five_validator_snapshot_migration_updates_envelope_length() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let validator = PrincipalId::new(Digest384::new([85; 48]));
        let signer = ValidatorSigner::from_seed(validator, [86; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(validator, 1, signer.public_key().try_into().unwrap())
                    .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-schema-five-validator-snapshot-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let state = ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root());
        let service = ValidatorService::from_genesis(state, &genesis, path.clone()).unwrap();
        service.propose_round(&signer, 1, 0, Digest384::new([87; 48]), 1).unwrap();
        let current = std::fs::read(&path).unwrap();
        let mut prefix_end = 4;
        let mut body_length = 0_u32;
        for index in 0..5 {
            let byte = current[prefix_end];
            prefix_end += 1;
            body_length |= u32::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                break;
            }
        }
        assert_eq!(prefix_end + body_length as usize, current.len());
        assert_eq!(&current[current.len() - 2..], &[0, 0]);
        let legacy_body = &current[prefix_end..current.len() - 2];
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&current[..2]);
        legacy.extend_from_slice(&5_u16.to_be_bytes());
        let mut remaining = legacy_body.len() as u32;
        loop {
            let mut byte = (remaining & 0x7f) as u8;
            remaining >>= 7;
            if remaining != 0 {
                byte |= 0x80;
            }
            legacy.push(byte);
            if remaining == 0 {
                break;
            }
        }
        legacy.extend_from_slice(legacy_body);
        std::fs::write(&path, legacy).unwrap();
        let restored = load_snapshot(&path).unwrap();
        assert_eq!(restored, service.state().unwrap());
        drop(service);
        let restarted = ValidatorService::from_genesis(restored, &genesis, path.clone()).unwrap();
        assert_eq!(restarted.state().unwrap(), restored);
        assert_eq!(u16::from_be_bytes(std::fs::read(&path).unwrap()[2..4].try_into().unwrap()), 6);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn live_socket_session_authenticates_before_processing_consensus() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let local = std::sync::Arc::new(ValidatorSigner::from_seed(
            PrincipalId::new(Digest384::new([71; 48])),
            [72; 32],
        ));
        let remote =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([72; 48])), [74; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    local.validator(),
                    1,
                    local.public_key().try_into().unwrap(),
                )
                .unwrap(),
                ValidatorGenesisEntry::new(
                    remote.validator(),
                    1,
                    remote.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("activechain-live-{}.bin", std::process::id()));
        let session_path = path.with_extension("sessions");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&session_path);
        let service = std::sync::Arc::new(
            ValidatorService::from_genesis(
                ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                &genesis,
                path.clone(),
            )
            .unwrap(),
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_service = std::sync::Arc::clone(&service);
        let server_signer = std::sync::Arc::clone(&local);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            server_service
                .serve_authenticated_genesis_peer_with_voting(
                    PeerSocket::connect(stream),
                    1,
                    &server_signer,
                )
                .unwrap();
        });
        let mut client = PeerSocket::connect(TcpStream::connect(address).unwrap());
        let session = client
            .initiate_pq_session(
                PqSessionContext {
                    chain: genesis.genesis_commitment(),
                    epoch: genesis.epoch(),
                    protocol_revision: genesis.protocol_revision(),
                    initiator: 2,
                    responder: 1,
                },
                &remote,
                &local.public_key(),
            )
            .unwrap();
        let proposal = sign_genesis_proposal(&local, &genesis, 1, 0, Digest384::new([75; 48]));
        client
            .send_protected_message(
                &session,
                1,
                &remote.sign_envelope(2, 1, ConsensusMessage::Proposal(proposal)).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            client.receive_protected_message(&session).unwrap().1.message,
            ConsensusMessage::Vote(_)
        ));
        drop(client);
        server.join().unwrap();
        assert_eq!(service.metrics().proposals, 1);
        assert_eq!(service.metrics().peer_sessions_established, 1);
        assert_eq!(service.metrics().peer_session_rejections, 0);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(session_path);
    }

    #[test]
    fn authenticated_rate_limit_is_reached_before_protected_frame_decode() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let local = Arc::new(ValidatorSigner::from_seed(
            PrincipalId::new(Digest384::new([141; 48])),
            [142; 32],
        ));
        let remote =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([143; 48])), [144; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    local.validator(),
                    1,
                    local.public_key().try_into().unwrap(),
                )
                .unwrap(),
                ValidatorGenesisEntry::new(
                    remote.validator(),
                    1,
                    remote.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir().join(format!(
            "activechain-rate-limit-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        let session_path = path.with_extension("sessions");
        let service = Arc::new(
            ValidatorService::from_genesis(
                ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                &genesis,
                path.clone(),
            )
            .unwrap(),
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (ready_sender, ready_receiver) = mpsc::channel();
        let (go_sender, go_receiver) = mpsc::channel();
        let server_service = Arc::clone(&service);
        let server_signer = Arc::clone(&local);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (mut peer, session) = server_service
                .authenticate_inbound_peer(PeerSocket::connect(stream), 1, &server_signer)
                .unwrap();
            ready_sender.send(()).unwrap();
            go_receiver.recv().unwrap();
            let limited = server_service.receive_session_message(&mut peer, &session).unwrap_err();
            assert_eq!(limited.kind(), std::io::ErrorKind::WouldBlock);
            server_service.authenticated_rate_limits.lock().unwrap().clear();
            server_service.receive_session_message(&mut peer, &session).unwrap()
        });

        let mut client = PeerSocket::connect(TcpStream::connect(address).unwrap());
        let session = client
            .initiate_pq_session(
                PqSessionContext {
                    chain: genesis.genesis_commitment(),
                    epoch: genesis.epoch(),
                    protocol_revision: genesis.protocol_revision(),
                    initiator: 2,
                    responder: 1,
                },
                &remote,
                &local.public_key(),
            )
            .unwrap();
        ready_receiver.recv().unwrap();
        let window = Instant::now();
        for _ in 0..MAX_AUTHENTICATED_MESSAGES_PER_SECOND {
            assert!(service.allow_authenticated_receive(2, window).unwrap());
        }
        let proposal = sign_genesis_proposal(&local, &genesis, 1, 0, Digest384::new([145; 48]));
        let sent = remote.sign_envelope(2, 1, ConsensusMessage::Proposal(proposal)).unwrap();
        client.send_protected_message(&session, 1, &sent).unwrap();
        go_sender.send(()).unwrap();
        assert_eq!(server.join().unwrap(), sent);
        assert_eq!(service.metrics().peer_rate_limited, 1);
        drop(client);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(session_path);
    }

    #[test]
    fn live_vote_sequence_is_local_durable_state_not_remote_sequence() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let local = std::sync::Arc::new(ValidatorSigner::from_seed(
            PrincipalId::new(Digest384::new([109; 48])),
            [110; 32],
        ));
        let remote =
            ValidatorSigner::from_seed(PrincipalId::new(Digest384::new([111; 48])), [112; 32]);
        let genesis = ValidatorGenesis::new(
            1,
            1,
            vec![
                ValidatorGenesisEntry::new(
                    local.validator(),
                    1,
                    local.public_key().try_into().unwrap(),
                )
                .unwrap(),
                ValidatorGenesisEntry::new(
                    remote.validator(),
                    1,
                    remote.public_key().try_into().unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-local-sequence-{}.bin", std::process::id()));
        let session_path = path.with_extension("sessions");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&session_path);
        let service = std::sync::Arc::new(
            ValidatorService::from_genesis(
                ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                &genesis,
                path.clone(),
            )
            .unwrap(),
        );
        service.reserve_sequence_range(1, 40, 1).unwrap();
        assert_eq!(service.next_sequence(1).unwrap(), 41);

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_service = std::sync::Arc::clone(&service);
        let server_signer = std::sync::Arc::clone(&local);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            server_service
                .serve_authenticated_genesis_peer_with_voting(
                    PeerSocket::connect(stream),
                    1,
                    &server_signer,
                )
                .unwrap();
        });
        let mut client = PeerSocket::connect(TcpStream::connect(address).unwrap());
        let session = client
            .initiate_pq_session(
                PqSessionContext {
                    chain: genesis.genesis_commitment(),
                    epoch: genesis.epoch(),
                    protocol_revision: genesis.protocol_revision(),
                    initiator: 2,
                    responder: 1,
                },
                &remote,
                &local.public_key(),
            )
            .unwrap();
        let proposal = sign_genesis_proposal(&local, &genesis, 1, 0, Digest384::new([114; 48]));
        client
            .send_protected_message(
                &session,
                1,
                &remote.sign_envelope(2, u64::MAX, ConsensusMessage::Proposal(proposal)).unwrap(),
            )
            .unwrap();
        let response = client.receive_protected_message(&session).unwrap().1;
        assert_eq!(response.envelope.sender(), 1);
        assert_eq!(response.envelope.sequence(), 41);
        assert!(matches!(response.message, ConsensusMessage::Vote(_)));
        drop(client);
        server.join().unwrap();
        assert_eq!(service.next_sequence(1).unwrap(), 42);
        assert!(matches!(
            service.next_sequence(2),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::SequenceOverflow))
        ));
        drop(service);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(session_path).unwrap();
    }

    #[test]
    fn live_socket_quorum_fan_in_finalizes_three_validator_qc() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let signers: Vec<_> = (0..3)
            .map(|index| {
                ValidatorSigner::from_seed(
                    activechain_protocol_types::PrincipalId::new(Digest384::new([81 + index; 48])),
                    [82 + index; 32],
                )
            })
            .collect();
        let genesis = ValidatorGenesis::new(
            1,
            1,
            signers
                .iter()
                .map(|signer| {
                    ValidatorGenesisEntry::new(
                        signer.validator(),
                        1,
                        signer.public_key().try_into().unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("activechain-live-qc-{}.bin", std::process::id()));
        let session_path = path.with_extension("sessions");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&session_path);
        let receiver = std::sync::Arc::new(
            ValidatorService::from_genesis(
                ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                &genesis,
                path.clone(),
            )
            .unwrap(),
        );
        let send = |sender: &ValidatorSigner,
                    sender_id: u16,
                    message: AuthenticatedConsensusMessage| {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let service = std::sync::Arc::clone(&receiver);
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let local_signer = ValidatorSigner::from_seed(
                    activechain_protocol_types::PrincipalId::new(Digest384::new([81; 48])),
                    [82; 32],
                );
                service
                    .serve_authenticated_genesis_peer(PeerSocket::connect(stream), 1, &local_signer)
                    .unwrap();
            });
            let mut client = PeerSocket::connect(TcpStream::connect(address).unwrap());
            let session = client
                .initiate_pq_session(
                    PqSessionContext {
                        chain: genesis.genesis_commitment(),
                        epoch: genesis.epoch(),
                        protocol_revision: genesis.protocol_revision(),
                        initiator: sender_id,
                        responder: 1,
                    },
                    sender,
                    &signers[0].public_key(),
                )
                .unwrap();
            client.send_protected_message(&session, 1, &message).unwrap();
            drop(client);
            server.join().unwrap();
        };
        let proposal = sign_genesis_proposal(&signers[0], &genesis, 1, 0, Digest384::new([92; 48]));
        let proposal_message =
            signers[0].sign_envelope(1, 1, ConsensusMessage::Proposal(proposal.clone())).unwrap();
        receiver.process_message(proposal_message).unwrap();
        let mut votes = Vec::new();
        for (index, signer) in signers.iter().enumerate() {
            receiver
                .process_message(
                    signer
                        .sign_envelope(
                            (index + 1) as u16,
                            10 + index as u64,
                            ConsensusMessage::Proposal(proposal.clone()),
                        )
                        .unwrap(),
                )
                .ok();
            let vote = receiver.engine.lock().unwrap().sign_current_vote(signer).unwrap();
            votes.push(
                signer
                    .sign_envelope(
                        (index + 1) as u16,
                        20 + index as u64,
                        ConsensusMessage::Vote(vote),
                    )
                    .unwrap(),
            );
        }
        for vote in votes {
            let sender_id = vote.envelope.sender();
            if sender_id == 1 {
                receiver.process_message(vote).unwrap();
            } else {
                send(&signers[sender_id as usize - 1], sender_id, vote);
            }
        }
        assert_eq!(receiver.state().unwrap().finalized_height(), 0);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(session_path);
    }

    #[test]
    fn timeout_quorum_rotates_leader_and_survives_restart() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let signers: Vec<_> = (0..3)
            .map(|index| {
                ValidatorSigner::from_seed(
                    PrincipalId::new(Digest384::new([140 + index; 48])),
                    [150 + index; 32],
                )
            })
            .collect();
        let genesis = ValidatorGenesis::new(
            1,
            1,
            signers
                .iter()
                .map(|signer| {
                    ValidatorGenesisEntry::new(
                        signer.validator(),
                        1,
                        signer.public_key().try_into().unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let path = std::env::temp_dir()
            .join(format!("activechain-view-change-restart-{}.bin", std::process::id()));
        let state = ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root());
        let service = ValidatorService::from_genesis(state, &genesis, path.clone()).unwrap();
        for (index, signer) in signers.iter().enumerate() {
            service
                .timeout_round(signer, 1, 0, 1)
                .unwrap_or_else(|error| panic!("validator {index} timeout vote failed: {error:?}"));
        }
        {
            let engine = service.engine.lock().unwrap();
            let certificate = engine.accepted_view_change.as_ref().unwrap();
            assert_eq!(certificate.timed_out_round(), 0);
            assert_eq!(certificate.next_round(), 1);
            assert_eq!(certificate.votes().len(), 3);
        }
        drop(service);

        let restarted = ValidatorService::from_genesis(state, &genesis, path.clone()).unwrap();
        assert_eq!(
            restarted.engine.lock().unwrap().accepted_view_change.as_ref().unwrap().next_round(),
            1
        );
        let published = restarted.publish_view_change(&signers[1], 8).unwrap();
        let receiver_path = std::env::temp_dir()
            .join(format!("activechain-view-change-receiver-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&receiver_path);
        let receiver =
            ValidatorService::from_genesis(state, &genesis, receiver_path.clone()).unwrap();
        receiver.process_message(published.clone()).unwrap();
        assert!(matches!(
            receiver.process_message(published),
            Err(ValidatorServiceError::Transport(TransportError::Replay))
        ));

        let context = ConsensusVoteContext::new(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
        )
        .unwrap();
        let parent = ConsensusBlockRef::new(
            genesis.genesis_commitment(),
            genesis.genesis_commitment(),
            0,
            0,
        )
        .unwrap();
        let mut forged_votes: Vec<_> = signers
            .iter()
            .map(|signer| signer.sign_timeout_vote(context, 1, 0, parent, None).unwrap())
            .collect();
        let unsigned = TimeoutVote::new(
            signers[2].validator(),
            context,
            1,
            0,
            parent,
            None,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap(),
        )
        .unwrap();
        forged_votes[2] = TimeoutVote::new(
            signers[2].validator(),
            context,
            1,
            0,
            parent,
            None,
            ProtocolSignature::new(
                CryptoSuiteId::ML_DSA_44,
                signers[0].key.sign(&unsigned.signing_payload()).encode().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let forged =
            ViewChangeCertificate::new(context, 1, 0, parent, None, 3, 3, forged_votes).unwrap();
        assert!(matches!(
            receiver.process_message(
                signers[0].sign_envelope(1, 9, ConsensusMessage::ViewChange(forged)).unwrap()
            ),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::InvalidViewChange))
        ));
        assert!(matches!(
            restarted.propose_round(&signers[0], 1, 1, Digest384::new([160; 48]), 2),
            Err(ValidatorServiceError::Engine(ValidatorEngineError::IneligibleProposer))
        ));
        let (proposal, _) =
            restarted.propose_round(&signers[1], 1, 1, Digest384::new([161; 48]), 10).unwrap();
        assert!(matches!(proposal.message, ConsensusMessage::Proposal(_)));
        drop(restarted);
        std::fs::remove_file(path).unwrap();
        drop(receiver);
        std::fs::remove_file(receiver_path).unwrap();
    }

    #[test]
    fn sustained_multi_round_quorum_rehearsal_preserves_monotonic_finality() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let signers: Vec<_> = (0..3)
            .map(|index| {
                ValidatorSigner::from_seed(
                    activechain_protocol_types::PrincipalId::new(Digest384::new([101 + index; 48])),
                    [102 + index; 32],
                )
            })
            .collect();
        let genesis = ValidatorGenesis::new(
            1,
            1,
            signers
                .iter()
                .map(|signer| {
                    ValidatorGenesisEntry::new(
                        signer.validator(),
                        1,
                        signer.public_key().try_into().unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let paths: Vec<_> = (0..3)
            .map(|index| {
                std::env::temp_dir()
                    .join(format!("activechain-soak-{}-{index}.bin", std::process::id()))
            })
            .collect();
        let services: Vec<_> = paths
            .iter()
            .map(|path| {
                ValidatorService::from_genesis(
                    ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                    &genesis,
                    path.clone(),
                )
                .unwrap()
            })
            .collect();
        for height in 1..=16 {
            let leader_index = ((height - 1) % 3) as usize;
            let sequence_base = height * 10;
            let (proposal, leader_vote) = services[leader_index]
                .propose_round(
                    &signers[leader_index],
                    height,
                    height - 1,
                    Digest384::new([height as u8; 48]),
                    sequence_base,
                )
                .unwrap();
            let mut votes = vec![leader_vote];
            for index in 0..3 {
                if index == leader_index {
                    continue;
                }
                let vote = services[index]
                    .process_proposal_and_sign_vote(
                        proposal.clone(),
                        &signers[index],
                        sequence_base + 2 + index as u64,
                    )
                    .unwrap();
                services[index].process_message(vote.clone()).unwrap();
                votes.push(vote);
            }
            for (service_index, service) in services.iter().enumerate() {
                for vote in &votes {
                    if vote.envelope.sender() != (service_index + 1) as u16 {
                        service.process_message(vote.clone()).unwrap();
                    }
                }
            }
            assert!(
                services
                    .iter()
                    .all(|service| service.state().unwrap().finalized_height() == height - 1)
            );
        }
        assert!(services.iter().all(|service| service.metrics().rejected_messages == 0));
        for path in paths {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn three_persistent_services_converge_after_authenticated_vote_fanout() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let ids: Vec<_> = (0..3)
            .map(|index| {
                activechain_protocol_types::PrincipalId::new(Digest384::new([index + 20; 48]))
            })
            .collect();
        let signers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(index, id)| ValidatorSigner::from_seed(*id, [index as u8 + 30; 32]))
            .collect();
        let entries = signers
            .iter()
            .map(|signer| {
                ValidatorGenesisEntry::new(
                    signer.validator(),
                    1,
                    signer.public_key().try_into().unwrap(),
                )
                .unwrap()
            })
            .collect();
        let genesis = ValidatorGenesis::new(1, 1, entries).unwrap();
        let paths: Vec<_> = (0..3)
            .map(|index| {
                std::env::temp_dir().join(format!(
                    "activechain-converge-{}-{}.bin",
                    std::process::id(),
                    index
                ))
            })
            .collect();
        let services: Vec<_> = paths
            .iter()
            .map(|path| {
                ValidatorService::from_genesis(
                    ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                    &genesis,
                    path.clone(),
                )
                .unwrap()
            })
            .collect();
        let (proposal, leader_vote) =
            services[0].propose_round(&signers[0], 1, 0, Digest384::new([21; 48]), 1).unwrap();
        let mut votes = vec![leader_vote];
        for index in 1..3 {
            votes.push(
                services[index]
                    .process_proposal_and_sign_vote(proposal.clone(), &signers[index], 2)
                    .unwrap(),
            );
        }
        for receiver in &services {
            for vote in &votes {
                let _ = receiver.process_message(vote.clone());
            }
        }
        assert!(services.iter().all(|service| service.state().unwrap().finalized_height() == 0));
        for path in paths {
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn peer_connector_bounds_configuration_and_reports_unreachable_peers() {
        assert!(PeerEndpoint::from_genesis_address(0, "127.0.0.1:1", vec![0; 1312]).is_err());
        assert!(PeerEndpoint::from_genesis_address(1, "not-an-address", vec![0; 1312]).is_err());
        assert_eq!(
            PeerEndpoint::from_genesis_address(1, "127.0.0.1:9", vec![0; 1312]).unwrap().id,
            1
        );
        let endpoint = PeerEndpoint {
            id: 1,
            address: "127.0.0.1:9".parse().unwrap(),
            public_key: vec![0; 1312],
        };
        let connector = PeerConnector::new(vec![endpoint.clone()])
            .unwrap()
            .with_retry_policy(1, Duration::from_millis(5), Duration::ZERO)
            .unwrap();
        assert!(connector.reconnect(&endpoint).is_err());
        assert!(matches!(
            PeerConnector::new(vec![PeerEndpoint {
                id: 1,
                address: "127.0.0.1:1".parse().unwrap(),
                public_key: vec![0; 3]
            }]),
            Err(PeerConnectorError::InvalidConfiguration)
        ));
    }

    #[test]
    fn partition_replay_and_late_vote_recovery_preserve_quorum_safety() {
        use activechain_protocol_types::{ValidatorGenesis, ValidatorGenesisEntry};
        let ids: Vec<_> = (0..3)
            .map(|index| {
                activechain_protocol_types::PrincipalId::new(Digest384::new([index + 40; 48]))
            })
            .collect();
        let signers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(index, id)| ValidatorSigner::from_seed(*id, [index as u8 + 50; 32]))
            .collect();
        let entries = signers
            .iter()
            .map(|signer| {
                ValidatorGenesisEntry::new(
                    signer.validator(),
                    1,
                    signer.public_key().try_into().unwrap(),
                )
                .unwrap()
            })
            .collect();
        let genesis = ValidatorGenesis::new(1, 1, entries).unwrap();
        let paths: Vec<_> = (0..3)
            .map(|index| {
                std::env::temp_dir().join(format!(
                    "activechain-fault-{}-{}.bin",
                    std::process::id(),
                    index
                ))
            })
            .collect();
        let services: Vec<_> = paths
            .iter()
            .map(|path| {
                ValidatorService::from_genesis(
                    ConsensusState::new_with_validator_set_root(1, genesis.validator_set_root()),
                    &genesis,
                    path.clone(),
                )
                .unwrap()
            })
            .collect();
        let (proposal, leader_vote) =
            services[0].propose_round(&signers[0], 1, 0, Digest384::new([41; 48]), 1).unwrap();
        let vote_one =
            services[1].process_proposal_and_sign_vote(proposal.clone(), &signers[1], 2).unwrap();
        let vote_two =
            services[2].process_proposal_and_sign_vote(proposal, &signers[2], 2).unwrap();
        assert!(services[0].process_message(vote_one.clone()).unwrap().is_none());
        assert_eq!(services[0].state().unwrap().finalized_height(), 0);
        assert!(matches!(
            services[0].process_message(leader_vote.clone()),
            Err(ValidatorServiceError::Transport(TransportError::Replay))
        ));
        for receiver in &services {
            let _ = receiver.process_message(vote_one.clone());
            let _ = receiver.process_message(vote_two.clone());
            let _ = receiver.process_message(leader_vote.clone());
        }
        assert!(services.iter().all(|service| service.state().unwrap().finalized_height() == 0));
        for path in paths {
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn vote_collection_rejects_duplicate_unknown_mismatched_and_under_threshold_votes() {
        use activechain_protocol_types::{PrincipalId, ValidatorWeight};
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([1; 32]));
        let id = PrincipalId::new(Digest384::new([1; 48]));
        let unknown = PrincipalId::new(Digest384::new([2; 48]));
        let set = ValidatorSet::new(vec![
            ValidatorWeight { validator: id, stake: 2 },
            ValidatorWeight { validator: unknown, stake: 1 },
        ])
        .unwrap();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2420]).unwrap();
        let genesis_commitment = Digest384::new([50; 48]);
        let validator_set_root = Digest384::new([51; 48]);
        let vote_context =
            ConsensusVoteContext::new(genesis_commitment, 1, validator_set_root).unwrap();
        let proposal = BlockProposal::new(
            id,
            vote_context,
            1,
            0,
            Digest384::new([3; 48]),
            genesis_justification(vote_context),
            placeholder.clone(),
        )
        .unwrap();
        let proposal_commitment = proposal.commitment();
        let make_vote = |validator, height, digest| {
            let unsigned = ValidatorVote::new(
                validator,
                vote_context,
                height,
                0,
                digest,
                proposal_commitment,
                placeholder.clone(),
            )
            .unwrap();
            ValidatorVote::new(
                validator,
                vote_context,
                height,
                0,
                digest,
                proposal_commitment,
                ProtocolSignature::new(
                    CryptoSuiteId::ML_DSA_44,
                    key.sign(&unsigned.signing_payload()).encode().to_vec(),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let valid = make_vote(id, 1, Digest384::new([3; 48]));
        let mut collector =
            VoteCollector::new(proposal.clone(), genesis_commitment, validator_set_root, 1);
        assert_eq!(
            collector.add_vote(&set, key.verifying_key().encode().as_slice(), valid.clone()),
            Ok(())
        );
        assert_eq!(
            collector.add_vote(&set, key.verifying_key().encode().as_slice(), valid),
            Err(VoteCollectionError::Duplicate)
        );
        assert_eq!(collector.finalize(1, &set), Err(VoteCollectionError::InsufficientStake));
        let mut collector =
            VoteCollector::new(proposal.clone(), genesis_commitment, validator_set_root, 1);
        assert_eq!(
            collector.add_vote(
                &set,
                key.verifying_key().encode().as_slice(),
                make_vote(id, 2, Digest384::new([3; 48]))
            ),
            Err(VoteCollectionError::ContextMismatch)
        );
        let outsider = PrincipalId::new(Digest384::new([9; 48]));
        let mut collector = VoteCollector::new(proposal, genesis_commitment, validator_set_root, 1);
        assert_eq!(
            collector.add_vote(
                &set,
                key.verifying_key().encode().as_slice(),
                make_vote(outsider, 1, Digest384::new([3; 48]))
            ),
            Err(VoteCollectionError::UnknownValidator)
        );
    }

    #[test]
    fn consensus_state_survives_restart_snapshot() {
        let validator_set_root = Digest384::new([7; 48]);
        let mut state = ConsensusState::new_with_validator_set_root(4, validator_set_root);
        let qc = QuorumCertificate::new(
            ConsensusVoteContext::new(Digest384::new([8; 48]), 4, validator_set_root).unwrap(),
            9,
            2,
            Digest384::new([1; 48]),
            Digest384::new([2; 48]),
            Digest384::new([3; 48]),
            10,
            7,
        )
        .unwrap();
        state.apply_committed_qc(&qc).unwrap();
        let path =
            std::env::temp_dir().join(format!("activechain-snapshot-{}.bin", std::process::id()));
        save_snapshot(&path, &state).unwrap();
        let restored = load_snapshot(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(restored.epoch(), 4);
        assert_eq!(restored.finalized_height(), 9);
        assert_eq!(restored.finalized_round(), 2);
    }

    #[test]
    fn distributed_snapshot_round_trips_through_authenticated_shards() {
        let state = ConsensusState::new_with_validator_set_root(4, Digest384::new([7; 48]));
        let path = std::env::temp_dir()
            .join(format!("activechain-distributed-{}.bin", std::process::id()));
        save_distributed_snapshot(&path, &state, 3, 2).unwrap();
        let restored = load_distributed_snapshot(&path).unwrap();
        assert_eq!(restored, state);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn runtime_opens_only_authenticated_canonical_protected_payloads() {
        let recipient = activechain_crypto_provider::MlKem768Recipient::from_seed([15; 64]);
        let snapshot = ConsensusState::new(3).snapshot();
        let protected = activechain_crypto_provider::ProtectedEnvelope::seal(
            &recipient.public_key(),
            &encode_envelope(&snapshot).unwrap(),
            b"chain-1",
        )
        .unwrap();
        let opened: ConsensusSnapshot =
            open_protected_payload(&protected.encode().unwrap(), &recipient, b"chain-1").unwrap();
        assert_eq!(opened, snapshot);
        assert!(
            open_protected_payload::<ConsensusSnapshot>(
                &protected.encode().unwrap(),
                &recipient,
                b"chain-2"
            )
            .is_err()
        );
    }

    #[test]
    fn remaining_peers_progress_after_peer_failure() {
        let mut supervisor = PeerSupervisor::new();
        let (sender, receiver) = std::sync::mpsc::channel();
        supervisor.spawn(move || {
            sender.send(1_u8).unwrap();
        });
        assert_eq!(receiver.recv().unwrap(), 1);
        supervisor.join_all().unwrap();
        let remaining_peer_ids = [1_u16, 2_u16];
        assert_eq!(remaining_peer_ids.len(), 2);
    }
}
#[cfg(all(test, unix))]
#[test]
fn validator_key_files_are_owner_only_manifest_bound_and_not_legacy_derived() {
    use activechain_protocol_types::{
        ML_DSA44_PUBLIC_KEY_LENGTH, ValidatorGenesis, ValidatorGenesisEntry,
    };
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let directory =
        std::env::temp_dir().join(format!("activechain-validator-keys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let key_path = directory.join("validator.key");
    let (validator, public_key) = provision_validator_key(&key_path).unwrap();
    assert_eq!(std::fs::metadata(&key_path).unwrap().mode() & 0o777, 0o600);
    let entry = ValidatorGenesisEntry::new(validator, 1, public_key.as_slice().try_into().unwrap())
        .unwrap();
    let genesis = ValidatorGenesis::new(1, 1, vec![entry.clone()]).unwrap();
    assert_eq!(
        ValidatorSigner::from_key_file(&key_path, &genesis, &entry).unwrap().public_key(),
        public_key
    );

    let symlink_path = directory.join("validator-link.key");
    std::os::unix::fs::symlink(&key_path, &symlink_path).unwrap();
    assert!(matches!(
        ValidatorSigner::from_key_file(&symlink_path, &genesis, &entry),
        Err(ValidatorKeyFileError::Io(_))
    ));
    let hardlink_path = directory.join("validator-hardlink.key");
    std::fs::hard_link(&key_path, &hardlink_path).unwrap();
    assert!(matches!(
        ValidatorSigner::from_key_file(&key_path, &genesis, &entry),
        Err(ValidatorKeyFileError::InvalidPermissions)
    ));
    std::fs::remove_file(hardlink_path).unwrap();

    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        ValidatorSigner::from_key_file(&key_path, &genesis, &entry),
        Err(ValidatorKeyFileError::InvalidPermissions)
    ));
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let other_path = directory.join("other.key");
    let (other_validator, other_public_key) = provision_validator_key(&other_path).unwrap();
    let other_entry = ValidatorGenesisEntry::new(
        other_validator,
        1,
        other_public_key.as_slice().try_into().unwrap(),
    )
    .unwrap();
    assert!(matches!(
        ValidatorSigner::from_key_file(&key_path, &genesis, &other_entry),
        Err(ValidatorKeyFileError::ManifestMismatch)
    ));

    let legacy_path = directory.join("legacy.key");
    let mut legacy_seed = [0_u8; 32];
    legacy_seed[..8].copy_from_slice(&0_u64.to_be_bytes());
    legacy_seed[8..16].copy_from_slice(&1_u64.to_be_bytes());
    legacy_seed[16..24].copy_from_slice(&1_u64.to_be_bytes());
    let legacy_signer = ValidatorSigner::from_seed(PrincipalId::new(Digest384::ZERO), legacy_seed);
    let legacy_public_key = legacy_signer.public_key();
    let legacy_entry = ValidatorGenesisEntry::new(
        validator_principal(&legacy_public_key),
        1,
        <[u8; ML_DSA44_PUBLIC_KEY_LENGTH]>::try_from(legacy_public_key.as_slice()).unwrap(),
    )
    .unwrap();
    let legacy_genesis = ValidatorGenesis::new(1, 1, vec![legacy_entry.clone()]).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&legacy_path)
        .unwrap();
    file.write_all(VALIDATOR_KEY_FILE_MAGIC).unwrap();
    file.write_all(&legacy_seed).unwrap();
    file.sync_all().unwrap();
    assert!(matches!(
        ValidatorSigner::from_key_file(&legacy_path, &legacy_genesis, &legacy_entry),
        Err(ValidatorKeyFileError::LegacyDeterministicKey)
    ));
    std::fs::remove_dir_all(directory).unwrap();
}
#[test]
fn atomic_persistence_files_with_one_stem_do_not_share_a_temporary_path() {
    let directory =
        std::env::temp_dir().join(format!("activechain-atomic-paths-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let snapshot = directory.join("validator.snapshot");
    let sessions = directory.join("validator.sessions");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let first_barrier = Arc::clone(&barrier);
    let first = std::thread::spawn(move || {
        first_barrier.wait();
        for _ in 0..32 {
            write_atomic(&snapshot, b"snapshot").unwrap();
        }
    });
    let second = std::thread::spawn(move || {
        barrier.wait();
        for _ in 0..32 {
            write_atomic(&sessions, b"sessions").unwrap();
        }
    });
    first.join().unwrap();
    second.join().unwrap();
    assert_eq!(std::fs::read(directory.join("validator.snapshot")).unwrap(), b"snapshot");
    assert_eq!(std::fs::read(directory.join("validator.sessions")).unwrap(), b"sessions");
    std::fs::remove_dir_all(directory).unwrap();
}
