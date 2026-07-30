#![forbid(unsafe_code)]

mod access;
mod faucet;

pub use access::{
    AccessCharge, RpcAccessController, load_access_terms, verify_access_terms, write_access_terms,
};
pub use faucet::{
    DurableFaucet, FaucetError, FaucetPolicy, FaucetReconciliation, SybilPolicy,
    faucet_abuse_identity, faucet_settlement_commitment,
};

use activechain_action_kernel::{ActionEnvelope, action_id};
use activechain_application_primitives::{DigestAnchorStatementV1, DurableAnchorRegistry};
use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_cash_kernel::{
    CoinCellMembershipProof, CoinCellRecord, CoinCellSet, FungibleCoinCellMembershipProof,
    FungibleCoinCellRecord, prove_coin_cell_membership,
};
use activechain_finality_types::commit_parts;
use activechain_protocol_types::{AssetId, ChainId, Digest384, Object, PrincipalId, TransactionId};
use activechain_rpc_types::{
    ActionSetProof, Health, MAX_SUPPORTED_PROOFS, ProofKind, QueryKind, QueryPage, QueryRecord,
    RpcAccessRequest, RpcAccessResponse, RpcError, RpcRequest, RpcResponse, RpcStatus,
};
use activechain_wallet_core::AuthorizedCashTransferV1;
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

/// Builds proof-bearing RPC records from a finalized cash cell set.
///
/// The finality bundle is validated before any record is returned. This keeps the
/// validator-to-index handoff fail-closed: a wallet snapshot or an unfinalized root
/// cannot be published as an RPC balance.
pub fn finalized_coin_cell_records(
    cells: &CoinCellSet,
    finalized_height: u64,
    finality: &[u8],
) -> Result<Vec<QueryRecord>, RpcStoreError> {
    let bundle = activechain_verifier_api::verify_finality_bundle(finality)
        .map_err(|_| RpcStoreError::Invalid)?;
    if bundle.header().inputs.height != finalized_height {
        return Err(RpcStoreError::Invalid);
    }
    let mut records = Vec::with_capacity(cells.as_slice().len());
    for cell in cells.as_slice() {
        let proof =
            prove_coin_cell_membership(cells, cell.id()).map_err(|_| RpcStoreError::Invalid)?;
        if proof.root().into_digest() != bundle.header().inputs.cash_cell_root
            || proof.record() != *cell
        {
            return Err(RpcStoreError::Invalid);
        }
        records.push(
            QueryRecord::new(
                QueryKind::CoinCell,
                cell.id().into_digest(),
                finalized_height,
                encode_envelope(cell).map_err(|_| RpcStoreError::Invalid)?,
                encode_envelope(&proof).map_err(|_| RpcStoreError::Invalid)?,
                finality.to_vec(),
            )
            .map_err(|_| RpcStoreError::Invalid)?,
        );
    }
    records.sort_by_key(|record| record.key());
    Ok(records)
}

/// Builds finalized Coin Cell records while binding the publisher to the
/// operator's configured chain genesis. This is the production entry point;
/// the legacy helper above remains useful for isolated fixtures.
pub fn finalized_coin_cell_records_with_chain_genesis(
    cells: &CoinCellSet,
    finalized_height: u64,
    finality: &[u8],
    chain_genesis: Digest384,
) -> Result<Vec<QueryRecord>, RpcStoreError> {
    let bundle = activechain_verifier_api::verify_finality_bundle_with_chain_genesis(
        finality,
        chain_genesis,
    )
    .map_err(|_| RpcStoreError::Invalid)?;
    if bundle.header().inputs.height != finalized_height {
        return Err(RpcStoreError::Invalid);
    }
    finalized_coin_cell_records(cells, finalized_height, finality)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcProofError {
    WrongKind,
    Malformed,
    Finality,
    Height,
    Key,
    Relation,
    Owner,
    Asset,
    Unsupported,
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

/// Verifies a finalized owner-scoped native Coin Cell record, including the
/// exact owner requested by a wallet.  The generic record verifier proves
/// membership in the finalized cash root; this boundary additionally prevents
/// a valid cell belonging to another principal from being accepted as a
/// wallet balance.
pub fn verify_owner_coin_cell_record_with_chain_genesis(
    record: &QueryRecord,
    owner: PrincipalId,
    chain_genesis: Digest384,
) -> Result<(), RpcProofError> {
    if record.kind() != QueryKind::CoinCell {
        return Err(RpcProofError::WrongKind);
    }
    let cell =
        decode_envelope::<CoinCellRecord>(record.value()).map_err(|_| RpcProofError::Malformed)?;
    if cell.cell().owner() != owner {
        return Err(RpcProofError::Owner);
    }
    verify_query_record_with_chain_genesis(record, chain_genesis)
}

/// Verifies a finalized owner- and asset-scoped fungible Coin Cell record.
pub fn verify_owner_fungible_coin_cell_record_with_chain_genesis(
    record: &QueryRecord,
    owner: PrincipalId,
    asset: AssetId,
    chain_genesis: Digest384,
) -> Result<(), RpcProofError> {
    if record.kind() != QueryKind::FungibleCoinCell {
        return Err(RpcProofError::WrongKind);
    }
    let cell = decode_envelope::<FungibleCoinCellRecord>(record.value())
        .map_err(|_| RpcProofError::Malformed)?;
    if cell.cell().owner() != owner {
        return Err(RpcProofError::Owner);
    }
    if cell.cell().asset_id() != asset {
        return Err(RpcProofError::Asset);
    }
    verify_query_record_with_chain_genesis(record, chain_genesis)
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
        QueryKind::CoinCell => {
            let cell = decode_envelope::<CoinCellRecord>(record.value())
                .map_err(|_| RpcProofError::Malformed)?;
            if cell.id().into_digest() != record.key() {
                return Err(RpcProofError::Key);
            }
            let proof = decode_envelope::<CoinCellMembershipProof>(record.proof())
                .map_err(|_| RpcProofError::Malformed)?;
            if proof.record() != cell
                || proof.root().into_digest() != finality.header().inputs.cash_cell_root
            {
                return Err(RpcProofError::Relation);
            }
            Ok(())
        }
        QueryKind::FungibleCoinCell => {
            let cell = decode_envelope::<FungibleCoinCellRecord>(record.value())
                .map_err(|_| RpcProofError::Malformed)?;
            if cell.id().into_digest() != record.key() {
                return Err(RpcProofError::Key);
            }
            let proof = decode_envelope::<FungibleCoinCellMembershipProof>(record.proof())
                .map_err(|_| RpcProofError::Malformed)?;
            if proof.record() != cell || proof.root() != finality.header().inputs.cash_cell_root {
                return Err(RpcProofError::Relation);
            }
            Ok(())
        }
        QueryKind::NonFungibleCoinCell => Err(RpcProofError::Unsupported),
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

    fn list_owner_coin_cells(
        &self,
        owner: PrincipalId,
        after: Option<Digest384>,
        limit: u16,
    ) -> Result<QueryPage, RpcStoreError> {
        let mut records = Vec::with_capacity(limit as usize);
        let mut has_more = false;
        for record in self.records.iter().filter(|record| {
            record.kind() == QueryKind::CoinCell
                && after.is_none_or(|key| record.key() > key)
                && decode_envelope::<CoinCellRecord>(record.value())
                    .is_ok_and(|cell| cell.cell().owner() == owner)
        }) {
            if records.len() == limit as usize {
                has_more = true;
                break;
            }
            records.push(record.clone());
        }
        let next = has_more.then(|| records.last().expect("a page with more has a record").key());
        QueryPage::new(records, next).map_err(|_| RpcStoreError::Invalid)
    }

    fn list_owner_fungible_coin_cells(
        &self,
        owner: PrincipalId,
        asset: AssetId,
        after: Option<Digest384>,
        limit: u16,
    ) -> Result<QueryPage, RpcStoreError> {
        let mut records = Vec::with_capacity(limit as usize);
        let mut has_more = false;
        for record in self.records.iter().filter(|record| {
            record.kind() == QueryKind::FungibleCoinCell
                && after.is_none_or(|key| record.key() > key)
                && decode_envelope::<FungibleCoinCellRecord>(record.value()).is_ok_and(|cell| {
                    cell.cell().owner() == owner && cell.cell().asset_id() == asset
                })
        }) {
            if records.len() == limit as usize {
                has_more = true;
                break;
            }
            records.push(record.clone());
        }
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
    const TYPE_TAG: u16 = 0x010c;
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
        let mut current = self.index.write().map_err(|_| RpcStoreError::Io)?;
        if next.chain_id != current.chain_id
            || next.genesis_commitment != current.genesis_commitment
            || next.finalized_height < current.finalized_height
        {
            return Err(RpcStoreError::Invalid);
        }
        *current = next;
        Ok(())
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

    pub fn replace_finalized_records(
        &self,
        expected_genesis: Digest384,
        finalized_height: u64,
        finalized_at_unix_seconds: u64,
        records: Vec<QueryRecord>,
    ) -> Result<(), RpcStoreError> {
        let current = self.index.read().map_err(|_| RpcStoreError::Io)?.clone();
        if current.genesis_commitment != expected_genesis
            || finalized_height < current.finalized_height
            || finalized_at_unix_seconds < current.finalized_at_unix_seconds
        {
            return Err(RpcStoreError::Invalid);
        }
        // Never persist an execution-produced record merely because its
        // envelope is well formed. Every record must independently prove the
        // same finalized chain and height before entering the durable index.
        for record in &records {
            if record.finalized_height() != finalized_height
                || verify_query_record_with_chain_genesis(record, expected_genesis).is_err()
            {
                return Err(RpcStoreError::Invalid);
            }
        }
        let next = RpcIndex::new(
            current.chain_id,
            current.genesis_commitment,
            current.protocol_revision,
            finalized_height,
            finalized_at_unix_seconds,
            current.maximum_staleness_seconds,
            current.supported_proofs,
            records,
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
            RpcRequest::ListOwnerCoinCells { owner, after, limit } => index
                .list_owner_coin_cells(owner, after, limit)
                .map_or(RpcResponse::Error(RpcError::Internal), RpcResponse::Page),
            RpcRequest::ListOwnerFungibleCoinCells { owner, asset, after, limit } => index
                .list_owner_fungible_coin_cells(owner, asset, after, limit)
                .map_or(RpcResponse::Error(RpcError::Internal), RpcResponse::Page),
            RpcRequest::SubmitAnchor { .. }
            | RpcRequest::ResolveAnchor { .. }
            | RpcRequest::RequestFaucet { .. }
            | RpcRequest::RequestAuthorizedFaucet { .. }
            | RpcRequest::ResolveFaucet { .. }
            | RpcRequest::FaucetTerms => RpcResponse::Error(RpcError::InvalidRequest),
        }
    }

    pub fn chain_id(&self) -> Result<ChainId, RpcStoreError> {
        self.index.read().map(|index| index.chain_id).map_err(|_| RpcStoreError::Io)
    }

    pub fn genesis_commitment(&self) -> Result<Digest384, RpcStoreError> {
        self.index.read().map(|index| index.genesis_commitment).map_err(|_| RpcStoreError::Io)
    }

    pub fn finalized_height(&self) -> Result<u64, RpcStoreError> {
        self.index.read().map(|index| index.finalized_height).map_err(|_| RpcStoreError::Io)
    }
}

type FaucetSettlement =
    dyn Fn(PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError> + Send + Sync;
type AuthorizedFaucetSettlement =
    dyn Fn(&[u8], PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError> + Send + Sync;

pub struct RpcServer {
    store: Arc<DurableRpcStore>,
    access: Option<Arc<RpcAccessController>>,
    anchors: Option<Arc<RwLock<DurableAnchorRegistry>>>,
    faucet: Option<Arc<RwLock<DurableFaucet>>>,
    faucet_settlement: Option<Arc<FaucetSettlement>>,
    authorized_faucet_settlement: Option<Arc<AuthorizedFaucetSettlement>>,
}

/// Production settlement boundary for faucet-authorized Coin Cell ingress.
/// Implementations must submit the exact recipient, amount, and faucet
/// reference and return only the validator-assigned transaction identifier.
pub trait FaucetSettlementAdapter: Send + Sync {
    fn settle(
        &self,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError>;
}

/// Typed production boundary for pre-signed faucet settlement. Implementors
/// must submit the exact envelope bytes after validating the expected fields.
pub trait AuthorizedFaucetSettlementAdapter: Send + Sync {
    fn settle_authorized(
        &self,
        envelope: &[u8],
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError>;
}

/// Direct validator-side adapter for deployments that host the authenticated
/// wallet ingress in the RPC process. The ingress remains durable and shared;
/// this boundary only admits exact signed envelopes.
pub struct WalletIngressAuthorizedSettlementAdapter {
    ingress: Arc<std::sync::Mutex<activechain_wallet_core::TransactionIngress>>,
    snapshot_path: PathBuf,
    finalized_state: Arc<DurableRpcStore>,
}

impl WalletIngressAuthorizedSettlementAdapter {
    pub fn new(
        ingress: Arc<std::sync::Mutex<activechain_wallet_core::TransactionIngress>>,
        snapshot_path: PathBuf,
        finalized_state: Arc<DurableRpcStore>,
    ) -> Self {
        Self { ingress, snapshot_path, finalized_state }
    }
}

impl AuthorizedFaucetSettlementAdapter for WalletIngressAuthorizedSettlementAdapter {
    fn settle_authorized(
        &self,
        envelope: &[u8],
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError> {
        let authorized = decode_envelope::<AuthorizedCashTransferV1>(envelope)
            .map_err(|_| FaucetError::InvalidTransition)?;
        let request = authorized.request();
        let transaction = request.intent_id().map_err(|_| FaucetError::InvalidTransition)?;
        self.finalized_state.reload().map_err(|_| FaucetError::Persistence)?;
        let chain_id = self.finalized_state.chain_id().map_err(|_| FaucetError::Persistence)?;
        if request.chain_id() != chain_id
            || request.transfer().recipient() != recipient
            || request.transfer().amount() != amount
            || request.settlement_reference() != Some(reference)
        {
            return Err(FaucetError::InvalidTransition);
        }
        let height =
            self.finalized_state.finalized_height().map_err(|_| FaucetError::Persistence)?;
        let mut ingress = self.ingress.lock().map_err(|_| FaucetError::Persistence)?;
        let transaction = TransactionId::new(transaction);
        if ingress.transaction_admitted(transaction) {
            return Ok(transaction);
        }
        ingress.submit_envelope_durable(envelope, height, &self.snapshot_path).map_err(
            |error| match error {
                activechain_wallet_core::WalletError::Persistence => FaucetError::Persistence,
                _ => FaucetError::InvalidTransition,
            },
        )?;
        Ok(transaction)
    }
}

impl<F> AuthorizedFaucetSettlementAdapter for F
where
    F: Fn(&[u8], PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError> + Send + Sync,
{
    fn settle_authorized(
        &self,
        envelope: &[u8],
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError> {
        self(envelope, recipient, amount, reference)
    }
}

impl<F> FaucetSettlementAdapter for F
where
    F: Fn(PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError> + Send + Sync,
{
    fn settle(
        &self,
        recipient: PrincipalId,
        amount: u128,
        reference: Digest384,
    ) -> Result<TransactionId, FaucetError> {
        self(recipient, amount, reference)
    }
}

impl RpcServer {
    pub fn new(store: Arc<DurableRpcStore>) -> Self {
        Self {
            store,
            access: None,
            anchors: None,
            faucet: None,
            faucet_settlement: None,
            authorized_faucet_settlement: None,
        }
    }

    pub fn with_anchor_registry(mut self, anchors: DurableAnchorRegistry) -> Self {
        self.anchors = Some(Arc::new(RwLock::new(anchors)));
        self
    }

    /// Attach the operator's durable faucet policy and receipt journal.
    /// Funding requests remain unavailable until a settlement adapter is wired;
    /// terms and receipt resolution are safe to expose independently.
    pub fn with_faucet(mut self, faucet: DurableFaucet) -> Self {
        self.faucet = Some(Arc::new(RwLock::new(faucet)));
        self
    }

    pub fn with_faucet_settlement<F>(mut self, settlement: F) -> Self
    where
        F: Fn(PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError>
            + Send
            + Sync
            + 'static,
    {
        self.faucet_settlement = Some(Arc::new(settlement));
        self
    }

    /// Attach the validator-backed settlement callback for pre-signed faucet
    /// envelopes. The callback receives the exact canonical bytes after
    /// faucet policy admission and must submit those bytes to ingress.
    pub fn with_authorized_faucet_settlement<F>(mut self, settlement: F) -> Self
    where
        F: Fn(&[u8], PrincipalId, u128, Digest384) -> Result<TransactionId, FaucetError>
            + Send
            + Sync
            + 'static,
    {
        self.authorized_faucet_settlement = Some(Arc::new(settlement));
        self
    }

    pub fn with_authorized_faucet_settlement_adapter<A>(self, adapter: A) -> Self
    where
        A: AuthorizedFaucetSettlementAdapter + 'static,
    {
        self.with_authorized_faucet_settlement(move |envelope, recipient, amount, reference| {
            adapter.settle_authorized(envelope, recipient, amount, reference)
        })
    }

    /// Attach a typed validator-backed settlement adapter. This is the
    /// production-facing equivalent of `with_faucet_settlement`.
    pub fn with_faucet_settlement_adapter<A>(self, adapter: A) -> Self
    where
        A: FaucetSettlementAdapter + 'static,
    {
        self.with_faucet_settlement(move |recipient, amount, reference| {
            adapter.settle(recipient, amount, reference)
        })
    }

    pub fn with_access(
        store: Arc<DurableRpcStore>,
        access: Arc<RpcAccessController>,
    ) -> Result<Self, RpcStoreError> {
        if store.chain_id()? != access.terms().chain_id() {
            return Err(RpcStoreError::Invalid);
        }
        Ok(Self {
            store,
            access: Some(access),
            anchors: None,
            faucet: None,
            faucet_settlement: None,
            authorized_faucet_settlement: None,
        })
    }

    #[cfg(test)]
    fn handle(&self, request: RpcRequest, now: u64) -> RpcResponse {
        self.handle_from_source(request, now, None)
    }

    fn handle_from_source(
        &self,
        request: RpcRequest,
        now: u64,
        abuse_identity: Option<Digest384>,
    ) -> RpcResponse {
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
            RpcRequest::FaucetTerms => {
                let Some(faucet) = &self.faucet else {
                    return RpcResponse::Error(RpcError::InvalidRequest);
                };
                let Ok(faucet) = faucet.read() else {
                    return RpcResponse::Error(RpcError::Internal);
                };
                match faucet.terms() {
                    Ok(terms) => RpcResponse::FaucetTerms(terms),
                    Err(_) => RpcResponse::Error(RpcError::Internal),
                }
            }
            RpcRequest::ResolveFaucet { reference } => {
                let Some(faucet) = &self.faucet else {
                    return RpcResponse::Error(RpcError::InvalidRequest);
                };
                let Ok(faucet) = faucet.read() else {
                    return RpcResponse::Error(RpcError::Internal);
                };
                faucet
                    .resolve(reference)
                    .cloned()
                    .map_or(RpcResponse::Error(RpcError::NotFound), RpcResponse::FaucetReceipt)
            }
            RpcRequest::RequestFaucet { request } => {
                let (Some(faucet), Some(settlement)) = (&self.faucet, &self.faucet_settlement)
                else {
                    return RpcResponse::Error(RpcError::InvalidRequest);
                };
                let Ok(mut faucet) = faucet.write() else {
                    return RpcResponse::Error(RpcError::Internal);
                };
                let Some(abuse_identity) = abuse_identity else {
                    return RpcResponse::Error(RpcError::InvalidRequest);
                };
                let Ok(request_bytes) = encode_envelope(request.as_ref()) else {
                    return RpcResponse::Error(RpcError::InvalidRequest);
                };
                match faucet.request(
                    &request,
                    abuse_identity,
                    faucet_settlement_commitment(&request_bytes),
                    now,
                    |recipient, amount, reference| settlement(recipient, amount, reference),
                ) {
                    Ok(receipt) => RpcResponse::FaucetReceipt(receipt),
                    Err(_) => RpcResponse::Error(RpcError::InvalidRequest),
                }
            }
            RpcRequest::RequestAuthorizedFaucet { request } => {
                let (Some(faucet), Some(settlement)) =
                    (&self.faucet, &self.authorized_faucet_settlement)
                else {
                    return RpcResponse::Error(RpcError::InvalidRequest);
                };
                let envelope = request.envelope.clone();
                let faucet_request = &request.request;
                let Ok(mut faucet) = faucet.write() else {
                    return RpcResponse::Error(RpcError::Internal);
                };
                let Some(abuse_identity) = abuse_identity else {
                    return RpcResponse::Error(RpcError::InvalidRequest);
                };
                match faucet.request(
                    faucet_request,
                    abuse_identity,
                    faucet_settlement_commitment(&envelope),
                    now,
                    |recipient, amount, reference| {
                        settlement(&envelope, recipient, amount, reference)
                    },
                ) {
                    Ok(receipt) => RpcResponse::FaucetReceipt(receipt),
                    Err(_) => RpcResponse::Error(RpcError::InvalidRequest),
                }
            }
            request => self.store.handle(request, now),
        }
    }

    pub fn serve_once(&self, listener: &TcpListener, now: u64) -> Result<(), RpcStoreError> {
        let (mut stream, peer) = listener.accept().map_err(|_| RpcStoreError::Io)?;
        let abuse_identity = match peer.ip() {
            std::net::IpAddr::V4(address) => {
                let mut identity = [0_u8; 5];
                identity[0] = 4;
                identity[1..].copy_from_slice(&address.octets());
                faucet_abuse_identity(&identity)
            }
            std::net::IpAddr::V6(address) => {
                let mut identity = [0_u8; 17];
                identity[0] = 6;
                identity[1..].copy_from_slice(&address.octets());
                faucet_abuse_identity(&identity)
            }
        };
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
                        response: self.handle_from_source(request, now, Some(abuse_identity)),
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
                self.handle_from_source(request, now, Some(abuse_identity))
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
    use activechain_cash_kernel::{
        CoinCell, CoinCellOrigin, CoinCellSet, CoinTransfer, GenesisAllocation, GenesisEconomy,
        NativeAssetDefinition, prove_coin_cell_membership,
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
        AccessManifest, AccessManifestFields, AuthenticatorDescriptor, AuthenticatorId,
        AuthenticatorPurpose, ConsensusVoteContext, CryptoSuiteId, FreezeState, JobId,
        ObjectFields, ObjectFlags, ObjectId, ObjectOwner, ObjectVersionRef, Principal, PrincipalId,
        PrincipalKind, ProtocolSignature, QuorumCertificate, TransactionId, ValidatorGenesis,
        ValidatorGenesisEntry, ValidatorVote,
    };
    use activechain_rpc_types::{
        ActionSetProof, AuthorizedFaucetRequestV1, FaucetRequestV1, MAX_RPC_PAGE_SIZE,
        RPC_SCHEMA_REVISION, RpcAccessMode, RpcAccessTerms,
    };
    use activechain_state_tree::{StateCommitment, commit_objects, prove_object};
    use activechain_transition::{TRANSFER_OBJECT_ACTION_ID, TransferCommand, TransferTransaction};
    use activechain_wallet_core::{
        AuthorizedCashSessionGrantV1, AuthorizedCashTransferV1, CashAuthorizationRequestV1,
        CashSessionGrantV1, FinalizedIdentityKeyProof, FinalizedIdentityKeyVerifier,
        TransactionIngress, authenticator_set_root,
    };
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use std::thread;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    #[test]
    fn typed_faucet_adapter_is_installed_on_rpc_server() {
        struct Adapter;
        impl FaucetSettlementAdapter for Adapter {
            fn settle(
                &self,
                _recipient: PrincipalId,
                _amount: u128,
                _reference: Digest384,
            ) -> Result<TransactionId, FaucetError> {
                Ok(TransactionId::new(digest(99)))
            }
        }
        struct AuthorizedAdapter;
        impl AuthorizedFaucetSettlementAdapter for AuthorizedAdapter {
            fn settle_authorized(
                &self,
                _envelope: &[u8],
                _recipient: PrincipalId,
                _amount: u128,
                reference: Digest384,
            ) -> Result<TransactionId, FaucetError> {
                Ok(TransactionId::new(reference))
            }
        }

        let path = temporary("typed-faucet-adapter");
        let _ = std::fs::remove_file(&path);
        let server =
            RpcServer::new(Arc::new(DurableRpcStore::create(path.clone(), index()).unwrap()))
                .with_faucet_settlement_adapter(Adapter)
                .with_authorized_faucet_settlement_adapter(AuthorizedAdapter);
        assert!(server.faucet_settlement.is_some());
        assert!(server.authorized_faucet_settlement.is_some());
        let _ = std::fs::remove_file(path);
    }

    struct AcceptIdentityFinality;

    impl FinalizedIdentityKeyVerifier for AcceptIdentityFinality {
        fn verify_finalized_identity_key(&self, _proof: &FinalizedIdentityKeyProof) -> bool {
            true
        }
    }

    fn authorized_cash_fixture()
    -> (TransactionIngress, SigningKey<MlDsa44>, PrincipalId, CoinTransfer) {
        let owner = PrincipalId::new(digest(10));
        let recipient = PrincipalId::new(digest(11));
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
        let mut ingress = TransactionIngress::from_genesis(&economy).unwrap();
        let key = SigningKey::<MlDsa44>::from_seed(&Seed::from([91; 32]));
        let authenticator = AuthenticatorDescriptor::new(
            AuthenticatorId::new(digest(91)),
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
            digest(31),
            digest(32),
            authenticator_set_root(core::slice::from_ref(&authenticator)).unwrap(),
            0,
            FreezeState::Active,
            digest(33),
            1,
            1,
            30,
        )
        .unwrap();
        ingress
            .install_finalized_authorization_key(
                &FinalizedIdentityKeyProof::new(
                    identity,
                    authenticator,
                    digest(34),
                    30,
                    digest(35),
                ),
                0,
                &AcceptIdentityFinality,
            )
            .unwrap();
        let cells = ingress.ledger().cells().as_slice();
        let transfer =
            CoinTransfer::new(owner, recipient, vec![cells[0].id()], cells[1].id(), 10, 1, 10)
                .unwrap();
        let grant = CashSessionGrantV1::new(ChainId::new(digest(1)), owner, digest(12), 1, 10, 100)
            .unwrap();
        let signature = key.sign(&grant.signing_payload().unwrap());
        ingress
            .register_session(
                &AuthorizedCashSessionGrantV1::new(
                    grant,
                    ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        (ingress, key, owner, transfer)
    }

    fn authorized_cash_envelope(
        key: &SigningKey<MlDsa44>,
        owner: PrincipalId,
        transfer: CoinTransfer,
        settlement_reference: Digest384,
    ) -> (Vec<u8>, Digest384) {
        let request = CashAuthorizationRequestV1::new_with_settlement_reference(
            ChainId::new(digest(1)),
            owner,
            0,
            digest(12),
            10,
            Some(settlement_reference),
            transfer,
        )
        .unwrap();
        let reference = request.intent_id().unwrap();
        let signature = key.sign(&request.signing_payload().unwrap());
        let envelope = encode_envelope(
            &AuthorizedCashTransferV1::new(
                request,
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        (envelope, reference)
    }

    #[test]
    fn production_faucet_adapter_persists_before_ack_and_reloads_finalized_height() {
        let (ingress, key, owner, transfer) = authorized_cash_fixture();
        let recipient = transfer.recipient();
        let settlement_reference = digest(70);
        let (envelope, transaction) =
            authorized_cash_envelope(&key, owner, transfer, settlement_reference);
        let index_path = temporary("authorized-faucet-index");
        let wallet_path = temporary("authorized-faucet-wallet");
        let _ = std::fs::remove_file(&index_path);
        let _ = std::fs::remove_file(&wallet_path);
        ingress.save_atomic(&wallet_path).unwrap();
        let finalized = Arc::new(DurableRpcStore::create(index_path.clone(), index()).unwrap());
        let shared = Arc::new(std::sync::Mutex::new(ingress));
        let adapter = WalletIngressAuthorizedSettlementAdapter::new(
            Arc::clone(&shared),
            wallet_path.clone(),
            Arc::clone(&finalized),
        );
        assert_eq!(
            adapter.settle_authorized(&envelope, recipient, 10, digest(99)),
            Err(FaucetError::InvalidTransition)
        );
        assert_eq!(
            adapter.settle_authorized(&envelope, recipient, 10, settlement_reference),
            Ok(TransactionId::new(transaction))
        );
        let restored = TransactionIngress::load(&wallet_path, ChainId::new(digest(1))).unwrap();
        assert_eq!(restored.next_nonce(owner), Some(1));
        assert_eq!(
            adapter.settle_authorized(&envelope, recipient, 10, settlement_reference),
            Ok(TransactionId::new(transaction))
        );
        let restarted_adapter = WalletIngressAuthorizedSettlementAdapter::new(
            Arc::new(std::sync::Mutex::new(
                TransactionIngress::load(&wallet_path, ChainId::new(digest(1))).unwrap(),
            )),
            wallet_path.clone(),
            Arc::clone(&finalized),
        );
        assert_eq!(
            restarted_adapter.settle_authorized(&envelope, recipient, 10, settlement_reference),
            Ok(TransactionId::new(transaction))
        );

        let (stale_ingress, stale_key, stale_owner, stale_transfer) = authorized_cash_fixture();
        let stale_recipient = stale_transfer.recipient();
        let stale_settlement_reference = digest(71);
        let (stale_envelope, _) = authorized_cash_envelope(
            &stale_key,
            stale_owner,
            stale_transfer,
            stale_settlement_reference,
        );
        let stale_wallet_path = temporary("authorized-faucet-stale-wallet");
        let _ = std::fs::remove_file(&stale_wallet_path);
        stale_ingress.save_atomic(&stale_wallet_path).unwrap();
        let writer = DurableRpcStore::load(index_path.clone()).unwrap();
        writer.advance_finality(digest(2), 11, 120).unwrap();
        let stale_adapter = WalletIngressAuthorizedSettlementAdapter::new(
            Arc::new(std::sync::Mutex::new(stale_ingress)),
            stale_wallet_path.clone(),
            finalized,
        );
        assert_eq!(
            stale_adapter.settle_authorized(
                &stale_envelope,
                stale_recipient,
                10,
                stale_settlement_reference,
            ),
            Err(FaucetError::InvalidTransition)
        );
        assert_eq!(
            TransactionIngress::load(&stale_wallet_path, ChainId::new(digest(1)))
                .unwrap()
                .next_nonce(stale_owner),
            Some(0)
        );

        let (network_ingress, network_key, network_owner, network_transfer) =
            authorized_cash_fixture();
        let network_recipient = network_transfer.recipient();
        let network_index_path = temporary("authorized-faucet-network-index");
        let network_wallet_path = temporary("authorized-faucet-network-wallet");
        let faucet_path = temporary("authorized-faucet-network-journal");
        for path in [&network_index_path, &network_wallet_path, &faucet_path] {
            let _ = std::fs::remove_file(path);
        }
        network_ingress.save_atomic(&network_wallet_path).unwrap();
        let network_store =
            Arc::new(DurableRpcStore::create(network_index_path.clone(), index()).unwrap());
        let network_adapter = WalletIngressAuthorizedSettlementAdapter::new(
            Arc::new(std::sync::Mutex::new(network_ingress)),
            network_wallet_path.clone(),
            Arc::clone(&network_store),
        );
        let faucet = DurableFaucet::create(
            FaucetPolicy {
                chain_id: ChainId::new(digest(1)),
                genesis_commitment: digest(2),
                testnet_only: true,
                enabled: true,
                policy_revision: 1,
                valid_until: 1_000,
                grant_amount: 10,
                recipient_cooldown_seconds: 1,
                recipient_lifetime_limit: 2,
                source_window_seconds: 60,
                source_window_limit: 2,
                global_window_seconds: 60,
                global_window_limit: 2,
                sybil_policy: SybilPolicy::CooldownOnly,
            },
            faucet_path.clone(),
        )
        .unwrap();
        let faucet_request = FaucetRequestV1::new(
            ChainId::new(digest(1)),
            digest(2),
            network_recipient,
            digest(61),
            digest(62),
            0,
            Vec::new(),
        )
        .unwrap();
        let network_settlement_reference = faucet_request.settlement_reference().unwrap();
        let (network_envelope, network_transaction) = authorized_cash_envelope(
            &network_key,
            network_owner,
            network_transfer,
            network_settlement_reference,
        );
        let server = RpcServer::new(network_store)
            .with_faucet(faucet)
            .with_authorized_faucet_settlement_adapter(network_adapter);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve_once(&listener, 105).unwrap());
        let response = query(
            address,
            &RpcRequest::RequestAuthorizedFaucet {
                request: Box::new(AuthorizedFaucetRequestV1 {
                    request: faucet_request,
                    envelope: network_envelope,
                }),
            },
        )
        .unwrap();
        handle.join().unwrap();
        let RpcResponse::FaucetReceipt(receipt) = response else {
            panic!("authorized faucet receipt expected")
        };
        assert_eq!(receipt.transaction_id(), Some(TransactionId::new(network_transaction)));
        assert_eq!(
            TransactionIngress::load(&network_wallet_path, ChainId::new(digest(1)))
                .unwrap()
                .next_nonce(network_owner),
            Some(1)
        );
        std::fs::remove_file(index_path).unwrap();
        std::fs::remove_file(wallet_path).unwrap();
        std::fs::remove_file(stale_wallet_path).unwrap();
        std::fs::remove_file(network_index_path).unwrap();
        std::fs::remove_file(network_wallet_path).unwrap();
        std::fs::remove_file(faucet_path).unwrap();
    }

    #[test]
    fn network_faucet_rate_limits_use_server_derived_peer_identity() {
        let index_path = temporary("faucet-peer-index");
        let faucet_path = temporary("faucet-peer-journal");
        let _ = std::fs::remove_file(&index_path);
        let _ = std::fs::remove_file(&faucet_path);
        let store = Arc::new(DurableRpcStore::create(index_path.clone(), index()).unwrap());
        let faucet = DurableFaucet::create(
            FaucetPolicy {
                chain_id: ChainId::new(digest(1)),
                genesis_commitment: digest(2),
                testnet_only: true,
                enabled: true,
                policy_revision: 1,
                valid_until: 1_000,
                grant_amount: 10,
                recipient_cooldown_seconds: 1,
                recipient_lifetime_limit: 2,
                source_window_seconds: 60,
                source_window_limit: 1,
                global_window_seconds: 60,
                global_window_limit: 3,
                sybil_policy: SybilPolicy::CooldownOnly,
            },
            faucet_path.clone(),
        )
        .unwrap();
        let settlements = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let settlement_counter = Arc::clone(&settlements);
        let server = Arc::new(RpcServer::new(store).with_faucet(faucet).with_faucet_settlement(
            move |_, _, _| {
                let sequence = settlement_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(TransactionId::new(digest(80 + sequence as u8)))
            },
        ));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        for (recipient, idempotency, client_source) in [(3, 40, 50), (4, 41, 51)] {
            let server = Arc::clone(&server);
            let listener = listener.try_clone().unwrap();
            let handle = thread::spawn(move || server.serve_once(&listener, 100).unwrap());
            let request = FaucetRequestV1::new(
                ChainId::new(digest(1)),
                digest(2),
                PrincipalId::new(digest(recipient)),
                digest(idempotency),
                digest(client_source),
                0,
                Vec::new(),
            )
            .unwrap();
            let _ =
                query(address, &RpcRequest::RequestFaucet { request: Box::new(request) }).unwrap();
            handle.join().unwrap();
        }

        assert_eq!(settlements.load(std::sync::atomic::Ordering::SeqCst), 1);
        std::fs::remove_file(index_path).unwrap();
        std::fs::remove_file(faucet_path).unwrap();
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
            header.proof_statement_commitment,
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
            header.proof_statement_commitment,
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
            header.proof_statement_commitment,
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
            cash_cell_root: digest(76),
            post_state,
            receipt_root: digest(77),
            data_availability_commitment: digest(75),
        }
    }
    fn receipt_record(byte: u8) -> QueryRecord {
        let pre_state = StateCommitment::new(digest(80), 0);
        let post_state = StateCommitment::new(digest(81), 0);
        let receipt = BlockReceipt::new(
            digest(byte),
            7,
            pre_state,
            post_state,
            digest(82),
            digest(83),
            vec![],
        )
        .unwrap();
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

    fn coin_cell_record(byte: u8, owner: PrincipalId) -> QueryRecord {
        let origin = CoinCellOrigin::new(TransactionId::new(digest(byte + 30)), 0);
        let id = activechain_protocol_commitment::coin_cell_id(&origin).unwrap();
        let cell = CoinCellRecord::new(id, CoinCell::new(origin, owner, 100, 1).unwrap());
        let cells = CoinCellSet::new(vec![cell]).unwrap();
        let proof = prove_coin_cell_membership(&cells, id).unwrap();
        let inputs = ProofPublicInputs {
            cash_cell_root: proof.root().into_digest(),
            ..public_inputs(
                StateCommitment::new(digest(80), 0),
                StateCommitment::new(digest(81), 0),
            )
        };
        QueryRecord::new(
            QueryKind::CoinCell,
            id.into_digest(),
            7,
            encode_envelope(&cell).unwrap(),
            encode_envelope(&proof).unwrap(),
            signed_finality(byte, inputs),
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
    fn owner_coin_cell_discovery_never_returns_another_owner() {
        let owner = PrincipalId::new(digest(40));
        let other = PrincipalId::new(digest(41));
        let mut base = index();
        let mut records = base.records.clone();
        records.push(coin_cell_record(1, owner));
        records.push(coin_cell_record(2, other));
        records.sort_by_key(|record| (record.kind(), record.key()));
        base = RpcIndex::new(
            base.chain_id,
            base.genesis_commitment,
            base.protocol_revision,
            base.finalized_height,
            base.finalized_at_unix_seconds,
            base.maximum_staleness_seconds,
            base.supported_proofs,
            records,
        )
        .unwrap();
        let path = temporary("owner-cells");
        let _ = std::fs::remove_file(&path);
        let store = DurableRpcStore::create(path.clone(), base).unwrap();
        let RpcResponse::Page(page) = store.handle(
            RpcRequest::ListOwnerCoinCells { owner, after: None, limit: MAX_RPC_PAGE_SIZE },
            105,
        ) else {
            panic!("owner page expected");
        };
        assert_eq!(page.records().len(), 1);
        let discovered = decode_envelope::<CoinCellRecord>(page.records()[0].value()).unwrap();
        assert_eq!(discovered.cell().owner(), owner);
        assert!(verify_query_record(&page.records()[0]).is_ok());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn owner_coin_cell_verification_binds_owner_and_chain_genesis() {
        let owner = PrincipalId::new(digest(44));
        let other = PrincipalId::new(digest(45));
        let record = coin_cell_record(44, owner);
        let bundle = activechain_verifier_api::verify_finality_bundle(record.finality()).unwrap();
        let genesis = bundle.validator_genesis().genesis_commitment();

        assert_eq!(
            verify_owner_coin_cell_record_with_chain_genesis(&record, owner, genesis),
            Ok(())
        );
        assert_eq!(
            verify_owner_coin_cell_record_with_chain_genesis(&record, other, genesis),
            Err(RpcProofError::Owner)
        );
        assert_eq!(
            verify_owner_coin_cell_record_with_chain_genesis(&record, owner, digest(250)),
            Err(RpcProofError::Finality)
        );
    }

    #[test]
    fn finalized_cash_publisher_rejects_cross_chain_finality() {
        let owner = PrincipalId::new(digest(46));
        let source = coin_cell_record(46, owner);
        let cell = decode_envelope::<CoinCellRecord>(source.value()).unwrap();
        let cells = CoinCellSet::new(vec![cell]).unwrap();
        let bundle = activechain_verifier_api::verify_finality_bundle(source.finality()).unwrap();
        let genesis = bundle.validator_genesis().genesis_commitment();
        assert!(
            finalized_coin_cell_records_with_chain_genesis(
                &cells,
                source.finalized_height(),
                source.finality(),
                genesis,
            )
            .is_ok()
        );
        assert_eq!(
            finalized_coin_cell_records_with_chain_genesis(
                &cells,
                source.finalized_height(),
                source.finality(),
                digest(251),
            ),
            Err(RpcStoreError::Invalid)
        );
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
        assert_eq!(RPC_SCHEMA_REVISION, 2);
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
