#![forbid(unsafe_code)]

mod access;

pub use access::{
    AccessCharge, RpcAccessController, load_access_terms, verify_access_terms, write_access_terms,
};

use activechain_action_kernel::{ActionEnvelope, action_id};
use activechain_application_primitives::{DigestAnchorStatementV1, DurableAnchorRegistry};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_finality_types::commit_parts;
use activechain_protocol_types::{ChainId, Digest384, Object, TransactionId};
use activechain_rpc_types::{
    ActionSetProof, Health, MAX_SUPPORTED_PROOFS, ProofKind, QueryKind, QueryPage, QueryRecord,
    RpcAccessRequest, RpcAccessResponse, RpcError, RpcRequest, RpcResponse, RpcStatus,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    fs::File,
    io::{Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

pub const MAX_RPC_FRAME: usize = 4 * 1024 * 1024;
pub const RPC_IO_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_INDEXED_RECORDS: usize = 65_535;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcProofError {
    WrongKind,
    Malformed,
    Finality,
    Height,
    Key,
    Relation,
}

pub fn verify_query_record(record: &QueryRecord) -> Result<(), RpcProofError> {
    let finality = activechain_verifier_api::verify_finality_bundle(record.finality())
        .map_err(|_| RpcProofError::Finality)?;
    verify_query_record_with_finality(record, finality, None)
}

pub fn verify_query_record_with_chain_genesis(
    record: &QueryRecord,
    chain_genesis: Digest384,
) -> Result<(), RpcProofError> {
    let finality = activechain_verifier_api::verify_finality_bundle_with_chain_genesis(
        record.finality(),
        chain_genesis,
    )
    .map_err(|_| RpcProofError::Finality)?;
    verify_query_record_with_finality(record, finality, Some(chain_genesis))
}

fn verify_query_record_with_finality(
    record: &QueryRecord,
    finality: activechain_finality_types::FinalityCertificateBundle,
    chain_genesis: Option<Digest384>,
) -> Result<(), RpcProofError> {
    if finality.header().inputs.height != record.finalized_height() {
        return Err(RpcProofError::Height);
    }
    match record.kind() {
        QueryKind::State => {
            let object =
                decode_envelope::<Object>(record.value()).map_err(|_| RpcProofError::Malformed)?;
            if object.object_id().into_digest() != record.key() {
                return Err(RpcProofError::Key);
            }
            let commitment = encode_envelope(&finality.header().inputs.post_state)
                .map_err(|_| RpcProofError::Malformed)?;
            activechain_verifier_api::verify_state_membership(
                &commitment,
                record.value(),
                record.proof(),
            )
            .map_err(|_| RpcProofError::Relation)
        }
        QueryKind::Action => {
            let action = decode_envelope::<ActionEnvelope>(record.value())
                .map_err(|_| RpcProofError::Malformed)?;
            let transaction_id = action_id(&action).map_err(|_| RpcProofError::Malformed)?;
            if *transaction_id.digest() != record.key() {
                return Err(RpcProofError::Key);
            }
            let proof = decode_envelope::<ActionSetProof>(record.proof())
                .map_err(|_| RpcProofError::Malformed)?;
            if proof.transaction_ids().binary_search(&transaction_id).is_err() {
                return Err(RpcProofError::Relation);
            }
            let mut ids = Vec::with_capacity(proof.transaction_ids().len() * 48);
            for id in proof.transaction_ids() {
                ids.extend_from_slice(id.digest().as_bytes());
            }
            let action_root = commit_parts(b"ACTIVECHAIN-BLOCK-ACTIONS-V1", &[&ids]);
            let execution_root = commit_parts(b"ACTIVECHAIN-BLOCK-EXECUTION-ORDER-V1", &[&ids]);
            if action_root != finality.header().inputs.action_root
                || execution_root != finality.header().inputs.execution_order_root
            {
                return Err(RpcProofError::Relation);
            }
            Ok(())
        }
        QueryKind::Receipt => {
            if !record.proof().is_empty() {
                return Err(RpcProofError::Malformed);
            }
            let receipt = if let Some(chain_genesis) = chain_genesis {
                activechain_verifier_api::verify_block_receipt_with_chain_genesis(
                    record.finality(),
                    record.value(),
                    chain_genesis,
                )
            } else {
                activechain_verifier_api::verify_block_receipt(record.finality(), record.value())
            }
            .map_err(|_| RpcProofError::Relation)?;
            if finality.header().inputs.receipt_root != record.key()
                || receipt.height() != record.finalized_height()
            {
                return Err(RpcProofError::Key);
            }
            Ok(())
        }
        QueryKind::ApplicationReceipt => {
            let receipt =
                activechain_application_primitives::verify_finalized_receipt_record(record)
                    .map_err(|_| RpcProofError::Malformed)?;
            let commitment = receipt.commitment().map_err(|_| RpcProofError::Malformed)?;
            let receipt_id = TransactionId::new(commitment);
            let proof = decode_envelope::<ActionSetProof>(record.proof())
                .map_err(|_| RpcProofError::Malformed)?;
            if proof.transaction_ids().binary_search(&receipt_id).is_err() {
                return Err(RpcProofError::Relation);
            }
            let mut ids = Vec::with_capacity(proof.transaction_ids().len() * 48);
            for id in proof.transaction_ids() {
                ids.extend_from_slice(id.digest().as_bytes());
            }
            let action_root = commit_parts(b"ACTIVECHAIN-BLOCK-ACTIONS-V1", &[&ids]);
            if action_root != finality.header().inputs.action_root {
                return Err(RpcProofError::Relation);
            }
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcIndex {
    chain_id: ChainId,
    genesis_commitment: Digest384,
    protocol_revision: u64,
    finalized_height: u64,
    finalized_at_unix_seconds: u64,
    maximum_staleness_seconds: u64,
    supported_proofs: Vec<ProofKind>,
    records: Vec<QueryRecord>,
}

impl RpcIndex {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        genesis_commitment: Digest384,
        protocol_revision: u64,
        finalized_height: u64,
        finalized_at_unix_seconds: u64,
        maximum_staleness_seconds: u64,
        supported_proofs: Vec<ProofKind>,
        records: Vec<QueryRecord>,
    ) -> Result<Self, RpcStoreError> {
        RpcStatus::new(
            chain_id,
            genesis_commitment,
            protocol_revision,
            finalized_height,
            finalized_at_unix_seconds,
            finalized_at_unix_seconds,
            maximum_staleness_seconds,
            supported_proofs.clone(),
        )
        .map_err(|_| RpcStoreError::Invalid)?;
        if records.len() > MAX_INDEXED_RECORDS
            || records.iter().any(|record| record.finalized_height() > finalized_height)
            || records.iter().any(|record| verify_query_record(record).is_err())
            || records
                .windows(2)
                .any(|pair| (pair[0].kind(), pair[0].key()) >= (pair[1].kind(), pair[1].key()))
        {
            return Err(RpcStoreError::Invalid);
        }
        Ok(Self {
            chain_id,
            genesis_commitment,
            protocol_revision,
            finalized_height,
            finalized_at_unix_seconds,
            maximum_staleness_seconds,
            supported_proofs,
            records,
        })
    }

    pub fn status(&self, now: u64) -> Result<RpcStatus, RpcStoreError> {
        RpcStatus::new(
            self.chain_id,
            self.genesis_commitment,
            self.protocol_revision,
            self.finalized_height,
            self.finalized_at_unix_seconds,
            now.max(self.finalized_at_unix_seconds),
            self.maximum_staleness_seconds,
            self.supported_proofs.clone(),
        )
        .map_err(|_| RpcStoreError::Invalid)
    }

    fn get(&self, kind: QueryKind, key: Digest384) -> Option<QueryRecord> {
        self.records
            .binary_search_by_key(&(kind, key), |record| (record.kind(), record.key()))
            .ok()
            .map(|position| self.records[position].clone())
    }

    fn list(
        &self,
        kind: QueryKind,
        after: Option<Digest384>,
        limit: u16,
    ) -> Result<QueryPage, RpcStoreError> {
        let mut matching = self
            .records
            .iter()
            .filter(|record| record.kind() == kind && after.is_none_or(|key| record.key() > key));
        let mut records = Vec::with_capacity(limit as usize);
        for _ in 0..limit {
            let Some(record) = matching.next() else { break };
            records.push(record.clone());
        }
        let has_more = matching.next().is_some();
        let next = has_more.then(|| records.last().expect("a page with more has a record").key());
        QueryPage::new(records, next).map_err(|_| RpcStoreError::Invalid)
    }
}

impl CanonicalEncode for RpcIndex {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.chain_id.encode(encoder)?;
        self.genesis_commitment.encode(encoder)?;
        self.protocol_revision.encode(encoder)?;
        self.finalized_height.encode(encoder)?;
        self.finalized_at_unix_seconds.encode(encoder)?;
        self.maximum_staleness_seconds.encode(encoder)?;
        encoder.write_length(self.supported_proofs.len(), MAX_SUPPORTED_PROOFS)?;
        for proof in &self.supported_proofs {
            proof.encode(encoder)?;
        }
        encoder.write_length(self.records.len(), MAX_INDEXED_RECORDS)?;
        for record in &self.records {
            record.encode(encoder)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for RpcIndex {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let chain_id = ChainId::decode(decoder)?;
        let genesis = Digest384::decode(decoder)?;
        let protocol = u64::decode(decoder)?;
        let height = u64::decode(decoder)?;
        let finalized_at = u64::decode(decoder)?;
        let staleness = u64::decode(decoder)?;
        let proof_count = decoder.read_length(MAX_SUPPORTED_PROOFS)?;
        let mut proofs = Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            proofs.push(ProofKind::decode(decoder)?);
        }
        let record_count = decoder.read_length(MAX_INDEXED_RECORDS)?;
        let mut records = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            records.push(QueryRecord::decode(decoder)?);
        }
        Self::new(chain_id, genesis, protocol, height, finalized_at, staleness, proofs, records)
            .map_err(|_| DecodeError::InvalidValue("invalid RPC index"))
    }
}
impl CanonicalType for RpcIndex {
    const TYPE_TAG: u16 = 0x00a2;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = MAX_RPC_FRAME - 32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcStoreError {
    Io,
    Invalid,
    Corrupt,
    TooLarge,
}

pub struct DurableRpcStore {
    path: PathBuf,
    index: RwLock<RpcIndex>,
}

impl DurableRpcStore {
    pub fn create(path: PathBuf, index: RpcIndex) -> Result<Self, RpcStoreError> {
        save_index(&path, &index)?;
        Ok(Self { path, index: RwLock::new(index) })
    }

    pub fn load(path: PathBuf) -> Result<Self, RpcStoreError> {
        let index = load_index(&path)?;
        Ok(Self { path, index: RwLock::new(index) })
    }

    pub fn replace(&self, next: RpcIndex) -> Result<(), RpcStoreError> {
        let mut current = self.index.write().map_err(|_| RpcStoreError::Io)?;
        if next.chain_id != current.chain_id
            || next.genesis_commitment != current.genesis_commitment
            || next.finalized_height < current.finalized_height
        {
            return Err(RpcStoreError::Invalid);
        }
        save_index(&self.path, &next)?;
        *current = next;
        Ok(())
    }

    pub fn reload(&self) -> Result<(), RpcStoreError> {
        let next = load_index(&self.path)?;
        self.replace(next)
    }

    pub fn advance_finality(
        &self,
        expected_genesis: Digest384,
        finalized_height: u64,
        finalized_at_unix_seconds: u64,
    ) -> Result<(), RpcStoreError> {
        let current = self.index.read().map_err(|_| RpcStoreError::Io)?.clone();
        if current.genesis_commitment != expected_genesis
            || finalized_height < current.finalized_height
            || finalized_at_unix_seconds < current.finalized_at_unix_seconds
        {
            return Err(RpcStoreError::Invalid);
        }
        let next = RpcIndex::new(
            current.chain_id,
            current.genesis_commitment,
            current.protocol_revision,
            finalized_height,
            finalized_at_unix_seconds,
            current.maximum_staleness_seconds,
            current.supported_proofs,
            current.records,
        )?;
        self.replace(next)
    }

    pub fn handle(&self, request: RpcRequest, now: u64) -> RpcResponse {
        let Ok(index) = self.index.read() else {
            return RpcResponse::Error(RpcError::Internal);
        };
        let status = match index.status(now) {
            Ok(status) => status,
            Err(_) => return RpcResponse::Error(RpcError::Internal),
        };
        if matches!(request, RpcRequest::Status) {
            return RpcResponse::Status(status);
        }
        if status.health() == Health::Stale {
            return RpcResponse::Error(RpcError::Stale);
        }
        match request {
            RpcRequest::Status => unreachable!(),
            RpcRequest::Get { kind, key } => index
                .get(kind, key)
                .map_or(RpcResponse::Error(RpcError::NotFound), RpcResponse::Record),
            RpcRequest::List { kind, after, limit } => index
                .list(kind, after, limit)
                .map_or(RpcResponse::Error(RpcError::Internal), RpcResponse::Page),
            RpcRequest::SubmitAnchor { .. } | RpcRequest::ResolveAnchor { .. } => {
                RpcResponse::Error(RpcError::InvalidRequest)
            }
        }
    }

    pub fn chain_id(&self) -> Result<ChainId, RpcStoreError> {
        self.index.read().map(|index| index.chain_id).map_err(|_| RpcStoreError::Io)
    }
}

pub struct RpcServer {
    store: Arc<DurableRpcStore>,
    access: Option<Arc<RpcAccessController>>,
    anchors: Option<Arc<RwLock<DurableAnchorRegistry>>>,
}
impl RpcServer {
    pub fn new(store: Arc<DurableRpcStore>) -> Self {
        Self { store, access: None, anchors: None }
    }

    pub fn with_anchor_registry(mut self, anchors: DurableAnchorRegistry) -> Self {
        self.anchors = Some(Arc::new(RwLock::new(anchors)));
        self
    }

    pub fn with_access(
        store: Arc<DurableRpcStore>,
        access: Arc<RpcAccessController>,
    ) -> Result<Self, RpcStoreError> {
        if store.chain_id()? != access.terms().chain_id() {
            return Err(RpcStoreError::Invalid);
        }
        Ok(Self { store, access: Some(access), anchors: None })
    }

    fn handle(&self, request: RpcRequest, now: u64) -> RpcResponse {
        match request {
            RpcRequest::SubmitAnchor { statement } => {
                let Some(anchors) = &self.anchors else {
                    return RpcResponse::Error(RpcError::InvalidRequest);
                };
                let Ok(statement) = decode_envelope::<DigestAnchorStatementV1>(&statement) else {
                    return RpcResponse::Error(RpcError::InvalidRequest);
                };
                let Ok(mut anchors) = anchors.write() else {
                    return RpcResponse::Error(RpcError::Internal);
                };
                match anchors.update(|registry| registry.submit(statement)) {
                    Ok(reference) => RpcResponse::AnchorSubmission(reference),
                    Err(_) => RpcResponse::Error(RpcError::Internal),
                }
            }
            RpcRequest::ResolveAnchor { reference } => {
                let Some(anchors) = &self.anchors else {
                    return RpcResponse::Error(RpcError::InvalidRequest);
                };
                let Ok(anchors) = anchors.read() else {
                    return RpcResponse::Error(RpcError::Internal);
                };
                let Some(record) = anchors.registry().resolve(reference) else {
                    return RpcResponse::Error(RpcError::NotFound);
                };
                match encode_envelope(record) {
                    Ok(record) => RpcResponse::AnchorRecord(record),
                    Err(_) => RpcResponse::Error(RpcError::Internal),
                }
            }
            request => self.store.handle(request, now),
        }
    }

    pub fn serve_once(&self, listener: &TcpListener, now: u64) -> Result<(), RpcStoreError> {
        let (mut stream, _) = listener.accept().map_err(|_| RpcStoreError::Io)?;
        self.store.reload()?;
        configure_stream(&stream)?;
        let request = read_frame(&mut stream)?;
        let response = if let Ok(request) = decode_envelope::<RpcAccessRequest>(&request) {
            let response = match request {
                RpcAccessRequest::Terms => {
                    let Some(access) = &self.access else {
                        return Err(RpcStoreError::Invalid);
                    };
                    RpcAccessResponse::Terms(access.terms().clone())
                }
                RpcAccessRequest::Execute { request, authorization } => {
                    let charge = if let Some(access) = &self.access {
                        match access.authorize(&request, authorization.as_deref(), now) {
                            Ok(charge) => charge,
                            Err(error) => {
                                let response = encode_envelope(&RpcAccessResponse::Denied(error))
                                    .map_err(|_| RpcStoreError::Invalid)?;
                                return write_frame(&mut stream, &response);
                            }
                        }
                    } else {
                        AccessCharge::free()
                    };
                    RpcAccessResponse::Response {
                        response: self.handle(request, now),
                        charged_units: charge.charged_units(),
                        remaining_units: charge.remaining_units(),
                    }
                }
            };
            encode_envelope(&response).map_err(|_| RpcStoreError::Invalid)?
        } else {
            let request =
                decode_envelope::<RpcRequest>(&request).map_err(|_| RpcStoreError::Invalid)?;
            let response = if self.access.as_ref().is_some_and(|access| !access.is_free())
                && !matches!(request, RpcRequest::Status)
            {
                RpcResponse::Error(RpcError::InvalidRequest)
            } else {
                self.handle(request, now)
            };
            encode_envelope(&response).map_err(|_| RpcStoreError::Invalid)?
        };
        write_frame(&mut stream, &response)
    }
}

pub fn query<A: ToSocketAddrs>(
    address: A,
    request: &RpcRequest,
) -> Result<RpcResponse, RpcStoreError> {
    let mut stream = TcpStream::connect(address).map_err(|_| RpcStoreError::Io)?;
    configure_stream(&stream)?;
    let request = encode_envelope(request).map_err(|_| RpcStoreError::Invalid)?;
    write_frame(&mut stream, &request)?;
    let response = read_frame(&mut stream)?;
    decode_envelope(&response).map_err(|_| RpcStoreError::Invalid)
}

pub fn query_with_access<A: ToSocketAddrs>(
    address: A,
    request: &RpcAccessRequest,
) -> Result<RpcAccessResponse, RpcStoreError> {
    let mut stream = TcpStream::connect(address).map_err(|_| RpcStoreError::Io)?;
    configure_stream(&stream)?;
    let request = encode_envelope(request).map_err(|_| RpcStoreError::Invalid)?;
    write_frame(&mut stream, &request)?;
    let response = read_frame(&mut stream)?;
    decode_envelope(&response).map_err(|_| RpcStoreError::Invalid)
}

fn configure_stream(stream: &TcpStream) -> Result<(), RpcStoreError> {
    stream.set_read_timeout(Some(RPC_IO_TIMEOUT)).map_err(|_| RpcStoreError::Io)?;
    stream.set_write_timeout(Some(RPC_IO_TIMEOUT)).map_err(|_| RpcStoreError::Io)
}
fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, RpcStoreError> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).map_err(|_| RpcStoreError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_RPC_FRAME {
        return Err(RpcStoreError::TooLarge);
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).map_err(|_| RpcStoreError::Io)?;
    Ok(body)
}
fn write_frame(stream: &mut TcpStream, body: &[u8]) -> Result<(), RpcStoreError> {
    if body.is_empty() || body.len() > MAX_RPC_FRAME {
        return Err(RpcStoreError::TooLarge);
    }
    let length = u32::try_from(body.len()).map_err(|_| RpcStoreError::TooLarge)?;
    stream.write_all(&length.to_be_bytes()).map_err(|_| RpcStoreError::Io)?;
    stream.write_all(body).map_err(|_| RpcStoreError::Io)
}

fn save_index(path: &Path, index: &RpcIndex) -> Result<(), RpcStoreError> {
    let bytes = encode_envelope(index).map_err(|_| RpcStoreError::Invalid)?;
    if bytes.len() + 32 > MAX_RPC_FRAME {
        return Err(RpcStoreError::TooLarge);
    }
    let tag = snapshot_tag(&bytes);
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary).map_err(|_| RpcStoreError::Io)?;
    file.write_all(&bytes).map_err(|_| RpcStoreError::Io)?;
    file.write_all(&tag).map_err(|_| RpcStoreError::Io)?;
    file.sync_all().map_err(|_| RpcStoreError::Io)?;
    std::fs::rename(&temporary, path).map_err(|_| RpcStoreError::Io)?;
    let parent =
        path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent).and_then(|directory| directory.sync_all()).map_err(|_| RpcStoreError::Io)
}
fn load_index(path: &Path) -> Result<RpcIndex, RpcStoreError> {
    let bytes = std::fs::read(path).map_err(|_| RpcStoreError::Io)?;
    if bytes.len() < 32 || bytes.len() > MAX_RPC_FRAME {
        return Err(RpcStoreError::Corrupt);
    }
    let body = bytes.len() - 32;
    if snapshot_tag(&bytes[..body]) != bytes[body..] {
        return Err(RpcStoreError::Corrupt);
    }
    decode_envelope(&bytes[..body]).map_err(|_| RpcStoreError::Corrupt)
}
fn snapshot_tag(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-RPC-INDEX-SNAPSHOT-V1");
    hasher.update(bytes);
    let mut output = [0; 32];
    XofReader::read(&mut hasher.finalize_xof(), &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_action_kernel::{
        ACTION_PROTOCOL_VERSION, FeeTicket, ResourceVector, ValidityInterval,
    };
    use activechain_application_primitives::{
        AnchorRecord, AnchorStatus, ApplicationReceipt, DigestAnchorStatementV1, JobStatus,
    };
    use activechain_devnet_kernel::BlockReceipt;
    use activechain_finality_types::{
        FinalityCertificateBundle, FinalizedBlockHeader, ProofPublicInputs,
    };
    use activechain_policy_kernel::{
        APL_LANGUAGE_VERSION, ActorBinding, PolicyRequest, PolicyRequestFields, PolicySet,
    };
    use activechain_protocol_commitment::{DomainTag, commit};
    use activechain_protocol_types::{
        AccessManifest, AccessManifestFields, ConsensusVoteContext, CryptoSuiteId, FreezeState,
        JobId, ObjectFields, ObjectFlags, ObjectId, ObjectOwner, ObjectVersionRef, PrincipalId,
        ProtocolSignature, QuorumCertificate, ValidatorGenesis, ValidatorGenesisEntry,
        ValidatorVote,
    };
    use activechain_rpc_types::{
        ActionSetProof, MAX_RPC_PAGE_SIZE, RPC_SCHEMA_REVISION, RpcAccessMode, RpcAccessTerms,
    };
    use activechain_state_tree::{StateCommitment, commit_objects, prove_object};
    use activechain_transition::{TRANSFER_OBJECT_ACTION_ID, TransferCommand, TransferTransaction};
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use std::thread;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn signed_finality(byte: u8, inputs: ProofPublicInputs) -> Vec<u8> {
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([byte; 32]));
        let validator = PrincipalId::new(digest(70));
        let genesis = ValidatorGenesis::new_with_revision(
            3,
            1,
            4,
            vec![
                ValidatorGenesisEntry::new(validator, 1, key.verifying_key().encode().into())
                    .unwrap(),
            ],
        )
        .unwrap();
        let header = FinalizedBlockHeader {
            inputs: ProofPublicInputs {
                validator_set_root: genesis.validator_set_root(),
                ..inputs
            },
            proof_statement_commitment: digest(76),
        };
        let context = ConsensusVoteContext::new_with_revision(
            genesis.genesis_commitment(),
            genesis.epoch(),
            genesis.validator_set_root(),
            genesis.protocol_revision(),
        )
        .unwrap();
        let unsigned = ValidatorVote::new(
            validator,
            context,
            7,
            2,
            header.digest().unwrap(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap(),
        )
        .unwrap();
        let signature = key.sign(&unsigned.signing_payload());
        let vote = ValidatorVote::new(
            validator,
            context,
            7,
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
        let mut vote_root = [0; 48];
        XofReader::read(&mut hasher.finalize_xof(), &mut vote_root);
        let certificate = QuorumCertificate::new(
            context,
            7,
            2,
            header.digest().unwrap(),
            Digest384::new(vote_root),
            1,
            1,
        )
        .unwrap();
        encode_envelope(
            &FinalityCertificateBundle::new(header, genesis, certificate, vec![vote]).unwrap(),
        )
        .unwrap()
    }
    fn public_inputs(pre_state: StateCommitment, post_state: StateCommitment) -> ProofPublicInputs {
        ProofPublicInputs {
            chain_id: ChainId::new(digest(1)),
            epoch: 3,
            height: 7,
            protocol_revision: 4,
            validator_set_root: digest(69),
            parent_block_id: digest(71),
            pre_state,
            authorization_root: digest(72),
            action_root: digest(73),
            execution_order_root: digest(74),
            total_fees: 0,
            pre_supply: 0,
            issuance: 0,
            burn: 0,
            post_supply: 0,
            post_state,
            receipt_root: digest(77),
            data_availability_commitment: digest(75),
        }
    }
    fn receipt_record(byte: u8) -> QueryRecord {
        let pre_state = StateCommitment::new(digest(80), 0);
        let post_state = StateCommitment::new(digest(81), 0);
        let receipt = BlockReceipt::new(digest(byte), 7, pre_state, post_state, vec![]).unwrap();
        let receipt_root = commit(DomainTag::CANONICAL_VALUE, &receipt).unwrap();
        let finality = signed_finality(
            byte,
            ProofPublicInputs { receipt_root, ..public_inputs(pre_state, post_state) },
        );
        QueryRecord::new(
            QueryKind::Receipt,
            receipt_root,
            7,
            encode_envelope(&receipt).unwrap(),
            vec![],
            finality,
        )
        .unwrap()
    }
    fn application_receipt_record() -> QueryRecord {
        let pre_state = StateCommitment::new(digest(80), 0);
        let post_state = StateCommitment::new(digest(81), 0);
        let job = JobId::new(digest(31));
        let receipt = ApplicationReceipt::new(
            job,
            digest(32),
            JobStatus::Completed,
            Some(digest(33)),
            7,
            7,
            digest(34),
        )
        .unwrap();
        let receipt_id = TransactionId::new(receipt.commitment().unwrap());
        let proof = ActionSetProof::new(vec![receipt_id]).unwrap();
        let ids = receipt_id.digest().as_bytes();
        let action_root = commit_parts(b"ACTIVECHAIN-BLOCK-ACTIONS-V1", &[ids]);
        let finality = signed_finality(
            31,
            ProofPublicInputs { action_root, ..public_inputs(pre_state, post_state) },
        );
        QueryRecord::new(
            QueryKind::ApplicationReceipt,
            job.into_digest(),
            7,
            encode_envelope(&receipt).unwrap(),
            encode_envelope(&proof).unwrap(),
            finality,
        )
        .unwrap()
    }
    fn action_envelope() -> ActionEnvelope {
        let actor = PrincipalId::new(digest(50));
        let object_id = ObjectId::new(digest(51));
        let input = ObjectVersionRef::new(object_id, 1);
        let manifest = AccessManifest::new(AccessManifestFields {
            exact_reads: vec![],
            exact_writes: vec![input],
            immutable_reads: vec![],
            creation_namespaces: vec![],
            maximum_created_objects: 0,
            maximum_dynamic_reads: 0,
            dynamic_read_policy: None,
        })
        .unwrap();
        let request = PolicyRequest::new(PolicyRequestFields {
            actor: ActorBinding::Principal(actor),
            action: TRANSFER_OBJECT_ACTION_ID,
            resource: object_id,
            height: 7,
            value: 0,
            freeze_state: FreezeState::Active,
            declared_purpose: None,
            credential_schemas: vec![],
            capabilities: vec![],
            approvals: vec![],
        })
        .unwrap();
        let transaction = TransferTransaction::new(
            7,
            manifest,
            vec![TransferCommand::new(
                input,
                ObjectOwner::Shared,
                PolicySet::new(APL_LANGUAGE_VERSION, vec![]).unwrap(),
                request,
            )],
        )
        .unwrap();
        let resources = ResourceVector::new(100, 0, 1, 0, 0, 2_000);
        ActionEnvelope::new(
            ACTION_PROTOCOL_VERSION,
            ChainId::new(digest(1)),
            actor,
            FeeTicket::new(
                ObjectId::new(digest(52)),
                PrincipalId::new(digest(53)),
                100_000,
                100,
                9,
                resources,
            )
            .unwrap(),
            2,
            5,
            ValidityInterval::new(1, 10).unwrap(),
            resources,
            commit(DomainTag::CANONICAL_VALUE, &transaction).unwrap(),
            transaction,
            digest(54),
        )
        .unwrap()
    }
    fn index() -> RpcIndex {
        let mut records = vec![
            receipt_record(10),
            receipt_record(11),
            receipt_record(12),
            receipt_record(13),
            receipt_record(14),
            receipt_record(20),
        ];
        records.sort_by_key(|record| (record.kind(), record.key()));
        RpcIndex::new(
            ChainId::new(digest(1)),
            digest(2),
            3,
            7,
            100,
            10,
            vec![ProofKind::FinalityCertificate, ProofKind::ReceiptCommitment],
            records,
        )
        .unwrap()
    }
    fn temporary(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "activechain-rpc-{name}-{}-{}.snapshot",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn durable_index_restarts_rejects_corruption_and_pages_without_skips() {
        let path = temporary("restart");
        let _ = std::fs::remove_file(&path);
        let store = DurableRpcStore::create(path.clone(), index()).unwrap();
        let page = store.handle(
            RpcRequest::List { kind: QueryKind::Receipt, after: None, limit: MAX_RPC_PAGE_SIZE },
            105,
        );
        let RpcResponse::Page(page) = page else { panic!("page expected") };
        assert_eq!(page.records().len(), 4);
        let cursor = page.next().unwrap();
        let RpcResponse::Page(next) = store.handle(
            RpcRequest::List {
                kind: QueryKind::Receipt,
                after: Some(cursor),
                limit: MAX_RPC_PAGE_SIZE,
            },
            105,
        ) else {
            panic!("next page expected")
        };
        assert!(!next.records().is_empty());
        assert!(next.records().iter().all(|record| verify_query_record(record) == Ok(())));
        drop(store);
        let restarted = DurableRpcStore::load(path.clone()).unwrap();
        assert!(matches!(
            restarted.handle(
                RpcRequest::Get { kind: QueryKind::Receipt, key: receipt_record(20).key() },
                105
            ),
            RpcResponse::Record(_)
        ));
        let mut corrupt = std::fs::read(&path).unwrap();
        corrupt[10] ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        assert!(matches!(DurableRpcStore::load(path.clone()), Err(RpcStoreError::Corrupt)));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn finalized_ingestion_is_monotonic_identity_bound_and_reloadable() {
        let path = temporary("ingestion");
        let _ = std::fs::remove_file(&path);
        let serving = DurableRpcStore::create(path.clone(), index()).unwrap();
        let writer = DurableRpcStore::load(path.clone()).unwrap();

        writer.advance_finality(digest(2), 8, 110).unwrap();
        serving.reload().unwrap();
        let RpcResponse::Status(status) = serving.handle(RpcRequest::Status, 110) else {
            panic!("status expected")
        };
        assert_eq!(status.finalized_height(), 8);
        assert_eq!(status.chain_id(), ChainId::new(digest(1)));
        assert_eq!(status.genesis_commitment(), digest(2));

        assert_eq!(writer.advance_finality(digest(9), 9, 120), Err(RpcStoreError::Invalid));
        assert_eq!(writer.advance_finality(digest(2), 7, 120), Err(RpcStoreError::Invalid));
        assert_eq!(writer.advance_finality(digest(2), 9, 90), Err(RpcStoreError::Invalid));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn anchor_rpc_submit_is_idempotent_and_survives_restart() {
        let index_path = temporary("anchor-index");
        let anchor_path = temporary("anchors");
        let _ = std::fs::remove_file(&index_path);
        let _ = std::fs::remove_file(&anchor_path);
        let store = Arc::new(DurableRpcStore::create(index_path.clone(), index()).unwrap());
        let server = RpcServer::new(store)
            .with_anchor_registry(DurableAnchorRegistry::open(&anchor_path).unwrap());
        let statement = DigestAnchorStatementV1::new(
            b"mademark.external-anchor.statement.v1".to_vec(),
            [42; 32],
        )
        .unwrap();
        let request = RpcRequest::SubmitAnchor { statement: encode_envelope(&statement).unwrap() };
        let RpcResponse::AnchorSubmission(reference) = server.handle(request.clone(), 105) else {
            panic!("anchor submission expected")
        };
        assert_eq!(server.handle(request, 105), RpcResponse::AnchorSubmission(reference));
        let RpcResponse::AnchorRecord(record) =
            server.handle(RpcRequest::ResolveAnchor { reference }, 105)
        else {
            panic!("anchor record expected")
        };
        let record = decode_envelope::<AnchorRecord>(&record).unwrap();
        assert_eq!(record.status(), AnchorStatus::Pending);
        drop(server);

        let store = Arc::new(DurableRpcStore::load(index_path.clone()).unwrap());
        let restarted = RpcServer::new(store)
            .with_anchor_registry(DurableAnchorRegistry::open(&anchor_path).unwrap());
        assert!(matches!(
            restarted.handle(RpcRequest::ResolveAnchor { reference }, 105),
            RpcResponse::AnchorRecord(_)
        ));
        let _ = std::fs::remove_file(index_path);
        let _ = std::fs::remove_file(anchor_path);
    }

    #[test]
    fn application_receipt_lookup_is_bound_to_finalized_ordered_commitment() {
        let record = application_receipt_record();
        assert_eq!(verify_query_record(&record), Ok(()));

        let substituted = QueryRecord::new(
            record.kind(),
            digest(99),
            record.finalized_height(),
            record.value().to_vec(),
            record.proof().to_vec(),
            record.finality().to_vec(),
        )
        .unwrap();
        assert_eq!(verify_query_record(&substituted), Err(RpcProofError::Malformed));
    }

    #[test]
    fn stale_queries_fail_closed_but_status_remains_available() {
        let path = temporary("stale");
        let _ = std::fs::remove_file(&path);
        let store = DurableRpcStore::create(path.clone(), index()).unwrap();
        assert!(matches!(
            store.handle(RpcRequest::Status, 111),
            RpcResponse::Status(status) if status.health() == Health::Stale
        ));
        assert_eq!(
            store.handle(
                RpcRequest::Get { kind: QueryKind::Receipt, key: receipt_record(10).key() },
                111
            ),
            RpcResponse::Error(RpcError::Stale)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn client_server_round_trip_returns_exact_proof_record() {
        let path = temporary("network");
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(DurableRpcStore::create(path.clone(), index()).unwrap());
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = RpcServer::new(store);
        let thread = thread::spawn(move || server.serve_once(&listener, 105));
        let response = query(
            address,
            &RpcRequest::Get { kind: QueryKind::Receipt, key: receipt_record(10).key() },
        )
        .unwrap();
        assert!(matches!(
            response,
            RpcResponse::Record(record) if verify_query_record(&record) == Ok(())
        ));
        thread.join().unwrap().unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn configured_free_access_supports_terms_wrappers_and_legacy_clients() {
        let terms = RpcAccessTerms::new(
            ChainId::new(digest(1)),
            digest(90),
            RpcAccessMode::Free,
            vec![],
            0,
            Digest384::ZERO,
            Digest384::ZERO,
            1,
            1,
            1,
            1_000,
            100,
            None,
        )
        .unwrap();
        let terms_path = temporary("access-terms");
        let usage_path = temporary("free-network");
        let _ = std::fs::remove_file(&terms_path);
        let _ = std::fs::remove_file(&usage_path);
        write_access_terms(&terms_path, &terms).unwrap();
        assert_eq!(load_access_terms(&terms_path), Ok(terms.clone()));
        let access = Arc::new(RpcAccessController::free(terms.clone()).unwrap());
        let store = Arc::new(DurableRpcStore::create(usage_path.clone(), index()).unwrap());
        let wrong_chain_terms = RpcAccessTerms::new(
            ChainId::new(digest(99)),
            digest(90),
            RpcAccessMode::Free,
            vec![],
            0,
            Digest384::ZERO,
            Digest384::ZERO,
            1,
            1,
            1,
            1_000,
            100,
            None,
        )
        .unwrap();
        let wrong_chain = Arc::new(RpcAccessController::free(wrong_chain_terms).unwrap());
        assert!(matches!(
            RpcServer::with_access(store.clone(), wrong_chain),
            Err(RpcStoreError::Invalid)
        ));

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = RpcServer::with_access(store.clone(), access.clone()).unwrap();
        let thread = thread::spawn(move || server.serve_once(&listener, 105));
        assert_eq!(
            query_with_access(address, &RpcAccessRequest::Terms).unwrap(),
            RpcAccessResponse::Terms(terms)
        );
        thread.join().unwrap().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = RpcServer::with_access(store, access).unwrap();
        let thread = thread::spawn(move || server.serve_once(&listener, 105));
        assert!(matches!(
            query(
                address,
                &RpcRequest::Get { kind: QueryKind::Receipt, key: receipt_record(10).key() },
            )
            .unwrap(),
            RpcResponse::Record(_)
        ));
        thread.join().unwrap().unwrap();
        let _ = std::fs::remove_file(terms_path);
        let _ = std::fs::remove_file(usage_path);
    }

    #[test]
    fn oversized_and_malformed_frames_are_rejected() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let path = temporary("malformed");
        let _ = std::fs::remove_file(&path);
        let server =
            RpcServer::new(Arc::new(DurableRpcStore::create(path.clone(), index()).unwrap()));
        let thread = thread::spawn(move || server.serve_once(&listener, 105));
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(&((MAX_RPC_FRAME as u32) + 1).to_be_bytes()).unwrap();
        assert_eq!(thread.join().unwrap(), Err(RpcStoreError::TooLarge));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn published_revisions_are_stable() {
        assert_eq!(RPC_SCHEMA_REVISION, 1);
        assert_eq!(RpcAccessTerms::TYPE_TAG, 0x00ba);
        assert_eq!(RpcAccessRequest::TYPE_TAG, 0x00bc);
        assert_eq!(RpcAccessResponse::TYPE_TAG, 0x00bd);
    }

    #[test]
    fn state_record_verifies_sparse_membership_against_cryptographic_finality() {
        let object = Object::new(ObjectFields {
            object_id: ObjectId::new(digest(30)),
            object_version: 1,
            type_id: digest(31),
            owner: ObjectOwner::Shared,
            control_policy_hash: digest(32),
            use_policy_hash: digest(33),
            disclosure_policy_hash: digest(34),
            upgrade_policy_hash: digest(35),
            package_id: None,
            value_root: digest(36),
            public_value: None,
            lease_expiry_epoch: 10,
            storage_deposit: 5,
            flags: ObjectFlags::TRANSFERABLE,
        })
        .unwrap();
        let objects = vec![object.clone()];
        let post_state = commit_objects(&objects).unwrap();
        let proof = prove_object(&objects, object.object_id()).unwrap();
        let inputs = ProofPublicInputs {
            post_state,
            ..public_inputs(commit_objects(&[]).unwrap(), post_state)
        };
        let record = QueryRecord::new(
            QueryKind::State,
            object.object_id().into_digest(),
            7,
            encode_envelope(&object).unwrap(),
            encode_envelope(&proof).unwrap(),
            signed_finality(42, inputs),
        )
        .unwrap();
        assert_eq!(verify_query_record(&record), Ok(()));
        let substituted = QueryRecord::new(
            QueryKind::State,
            ObjectId::new(digest(43)).into_digest(),
            7,
            record.value().to_vec(),
            record.proof().to_vec(),
            record.finality().to_vec(),
        )
        .unwrap();
        assert_eq!(verify_query_record(&substituted), Err(RpcProofError::Key));
    }

    #[test]
    fn action_record_verifies_full_ordered_set_against_both_finalized_roots() {
        let action = action_envelope();
        let id = action_id(&action).unwrap();
        let proof = ActionSetProof::new(vec![id]).unwrap();
        let mut id_bytes = Vec::new();
        id_bytes.extend_from_slice(id.digest().as_bytes());
        let empty = commit_objects(&[]).unwrap();
        let inputs = ProofPublicInputs {
            action_root: commit_parts(b"ACTIVECHAIN-BLOCK-ACTIONS-V1", &[&id_bytes]),
            execution_order_root: commit_parts(
                b"ACTIVECHAIN-BLOCK-EXECUTION-ORDER-V1",
                &[&id_bytes],
            ),
            ..public_inputs(empty, empty)
        };
        let record = QueryRecord::new(
            QueryKind::Action,
            *id.digest(),
            7,
            encode_envelope(&action).unwrap(),
            encode_envelope(&proof).unwrap(),
            signed_finality(55, inputs),
        )
        .unwrap();
        assert_eq!(verify_query_record(&record), Ok(()));

        let wrong =
            ActionSetProof::new(vec![activechain_protocol_types::TransactionId::new(digest(56))])
                .unwrap();
        let substituted = QueryRecord::new(
            QueryKind::Action,
            *id.digest(),
            7,
            record.value().to_vec(),
            encode_envelope(&wrong).unwrap(),
            record.finality().to_vec(),
        )
        .unwrap();
        assert_eq!(verify_query_record(&substituted), Err(RpcProofError::Relation));
    }
}
