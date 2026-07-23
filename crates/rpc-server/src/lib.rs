#![forbid(unsafe_code)]

use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_types::{ChainId, Digest384};
use activechain_rpc_types::{
    Health, MAX_SUPPORTED_PROOFS, ProofKind, QueryKind, QueryPage, QueryRecord, RpcError,
    RpcRequest, RpcResponse, RpcStatus,
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
        }
    }
}

pub struct RpcServer {
    store: Arc<DurableRpcStore>,
}
impl RpcServer {
    pub fn new(store: Arc<DurableRpcStore>) -> Self {
        Self { store }
    }

    pub fn serve_once(&self, listener: &TcpListener, now: u64) -> Result<(), RpcStoreError> {
        let (mut stream, _) = listener.accept().map_err(|_| RpcStoreError::Io)?;
        configure_stream(&stream)?;
        let request = read_frame(&mut stream)?;
        let request =
            decode_envelope::<RpcRequest>(&request).map_err(|_| RpcStoreError::Invalid)?;
        let response = encode_envelope(&self.store.handle(request, now))
            .map_err(|_| RpcStoreError::Invalid)?;
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
    hasher.finalize_xof().read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_rpc_types::{MAX_RPC_PAGE_SIZE, RPC_SCHEMA_REVISION};
    use std::thread;

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn record(kind: QueryKind, byte: u8) -> QueryRecord {
        QueryRecord::new(kind, digest(byte), 7, vec![byte], vec![byte + 1], vec![byte + 2]).unwrap()
    }
    fn index() -> RpcIndex {
        RpcIndex::new(
            ChainId::new(digest(1)),
            digest(2),
            3,
            7,
            100,
            10,
            vec![ProofKind::StateSparseMerkle, ProofKind::FinalityCertificate],
            vec![
                record(QueryKind::State, 10),
                record(QueryKind::State, 11),
                record(QueryKind::State, 12),
                record(QueryKind::State, 13),
                record(QueryKind::State, 14),
                record(QueryKind::Receipt, 20),
            ],
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
            RpcRequest::List { kind: QueryKind::State, after: None, limit: MAX_RPC_PAGE_SIZE },
            105,
        );
        let RpcResponse::Page(page) = page else { panic!("page expected") };
        assert_eq!(page.records().len(), 4);
        let cursor = page.next().unwrap();
        let RpcResponse::Page(next) = store.handle(
            RpcRequest::List {
                kind: QueryKind::State,
                after: Some(cursor),
                limit: MAX_RPC_PAGE_SIZE,
            },
            105,
        ) else {
            panic!("next page expected")
        };
        assert_eq!(next.records()[0].key(), digest(14));
        drop(store);
        let restarted = DurableRpcStore::load(path.clone()).unwrap();
        assert!(matches!(
            restarted.handle(RpcRequest::Get { kind: QueryKind::Receipt, key: digest(20) }, 105),
            RpcResponse::Record(_)
        ));
        let mut corrupt = std::fs::read(&path).unwrap();
        corrupt[10] ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        assert!(matches!(DurableRpcStore::load(path.clone()), Err(RpcStoreError::Corrupt)));
        let _ = std::fs::remove_file(path);
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
            store.handle(RpcRequest::Get { kind: QueryKind::State, key: digest(10) }, 111),
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
        let response =
            query(address, &RpcRequest::Get { kind: QueryKind::State, key: digest(10) }).unwrap();
        assert!(matches!(
            response,
            RpcResponse::Record(record)
                if record.value() == [10] && record.proof() == [11] && record.finality() == [12]
        ));
        thread.join().unwrap().unwrap();
        let _ = std::fs::remove_file(path);
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
    }
}
