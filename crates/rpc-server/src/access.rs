use activechain_canonical_codec::{
    CanonicalDecode, CanonicalEncode, CanonicalType, DecodeError, Decoder, EncodeError, Encoder,
    decode_envelope, encode_envelope,
};
use activechain_protocol_types::Digest384;
use activechain_rpc_types::{
    RpcAccessAuthorization, RpcAccessError, RpcAccessMode, RpcAccessRequest, RpcAccessTerms,
    RpcRequest,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

const MAX_USAGE_RECORDS: usize = 65_535;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessCharge {
    charged_units: u64,
    remaining_units: Option<u64>,
}
impl AccessCharge {
    pub const fn free() -> Self {
        Self { charged_units: 0, remaining_units: None }
    }
    pub const fn charged_units(self) -> u64 {
        self.charged_units
    }
    pub const fn remaining_units(self) -> Option<u64> {
        self.remaining_units
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UsageRecord {
    grant_id: Digest384,
    next_sequence: u64,
    spent_units: u64,
}
impl CanonicalEncode for UsageRecord {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.grant_id.encode(encoder)?;
        self.next_sequence.encode(encoder)?;
        self.spent_units.encode(encoder)
    }
}
impl CanonicalDecode for UsageRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            grant_id: Digest384::decode(decoder)?,
            next_sequence: u64::decode(decoder)?,
            spent_units: u64::decode(decoder)?,
        };
        if value.grant_id == Digest384::ZERO || value.next_sequence == 0 {
            return Err(DecodeError::InvalidValue("invalid RPC usage record"));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UsageState {
    access_scope: Digest384,
    records: Vec<UsageRecord>,
}
impl UsageState {
    fn empty(access_scope: Digest384) -> Self {
        Self { access_scope, records: Vec::new() }
    }
}
impl CanonicalEncode for UsageState {
    fn encode(&self, encoder: &mut Encoder) -> Result<(), EncodeError> {
        self.access_scope.encode(encoder)?;
        encoder.write_length(self.records.len(), MAX_USAGE_RECORDS)?;
        for record in &self.records {
            record.encode(encoder)?;
        }
        Ok(())
    }
}
impl CanonicalDecode for UsageState {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let access_scope = Digest384::decode(decoder)?;
        let count = decoder.read_length(MAX_USAGE_RECORDS)?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(UsageRecord::decode(decoder)?);
        }
        if access_scope == Digest384::ZERO
            || records.windows(2).any(|pair| pair[0].grant_id >= pair[1].grant_id)
        {
            return Err(DecodeError::InvalidValue("invalid RPC usage state"));
        }
        Ok(Self { access_scope, records })
    }
}
impl CanonicalType for UsageState {
    const TYPE_TAG: u16 = 0x00be;
    const SCHEMA_VERSION: u16 = 1;
    const MAX_ENCODED_LEN: usize = 48 + 3 + MAX_USAGE_RECORDS * 64;
}

pub struct RpcAccessController {
    terms: RpcAccessTerms,
    usage_path: Option<PathBuf>,
    usage: Mutex<UsageState>,
}

pub fn write_access_terms(path: &Path, terms: &RpcAccessTerms) -> Result<(), RpcAccessError> {
    let bytes = encode_envelope(terms).map_err(|_| RpcAccessError::Persistence)?;
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary).map_err(|_| RpcAccessError::Persistence)?;
    file.write_all(&bytes).map_err(|_| RpcAccessError::Persistence)?;
    file.sync_all().map_err(|_| RpcAccessError::Persistence)?;
    std::fs::rename(&temporary, path).map_err(|_| RpcAccessError::Persistence)?;
    let parent =
        path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RpcAccessError::Persistence)
}

pub fn load_access_terms(path: &Path) -> Result<RpcAccessTerms, RpcAccessError> {
    let length = std::fs::metadata(path).map_err(|_| RpcAccessError::Persistence)?.len();
    if length == 0 || length > (RpcAccessTerms::MAX_ENCODED_LEN + 8) as u64 {
        return Err(RpcAccessError::InvalidGrant);
    }
    let bytes = std::fs::read(path).map_err(|_| RpcAccessError::Persistence)?;
    decode_envelope(&bytes).map_err(|_| RpcAccessError::InvalidGrant)
}

pub fn verify_access_terms(
    terms: &RpcAccessTerms,
    expected_chain: activechain_protocol_types::ChainId,
    expected_operator: Digest384,
    now: u64,
) -> Result<(), RpcAccessError> {
    if terms.chain_id() != expected_chain
        || terms.operator_id() != expected_operator
        || now > terms.quote_valid_until()
    {
        return Err(RpcAccessError::InvalidGrant);
    }
    if terms.mode() == RpcAccessMode::Free { Ok(()) } else { verify_terms(terms) }
}

impl RpcAccessController {
    pub fn free(terms: RpcAccessTerms) -> Result<Self, RpcAccessError> {
        if terms.mode() != RpcAccessMode::Free {
            return Err(RpcAccessError::InvalidGrant);
        }
        let scope = access_scope(&terms);
        Ok(Self { terms, usage_path: None, usage: Mutex::new(UsageState::empty(scope)) })
    }

    pub fn create(terms: RpcAccessTerms, usage_path: PathBuf) -> Result<Self, RpcAccessError> {
        if terms.mode() == RpcAccessMode::Free {
            return Err(RpcAccessError::InvalidGrant);
        }
        verify_terms(&terms)?;
        let usage = UsageState::empty(access_scope(&terms));
        save_usage(&usage_path, &usage)?;
        Ok(Self { terms, usage_path: Some(usage_path), usage: Mutex::new(usage) })
    }

    pub fn load(terms: RpcAccessTerms, usage_path: PathBuf) -> Result<Self, RpcAccessError> {
        if terms.mode() == RpcAccessMode::Free {
            return Err(RpcAccessError::InvalidGrant);
        }
        verify_terms(&terms)?;
        let usage = load_usage(&usage_path)?;
        if usage.access_scope != access_scope(&terms) {
            return Err(RpcAccessError::InvalidGrant);
        }
        Ok(Self { terms, usage_path: Some(usage_path), usage: Mutex::new(usage) })
    }

    pub const fn terms(&self) -> &RpcAccessTerms {
        &self.terms
    }
    pub fn is_free(&self) -> bool {
        self.terms.mode() == RpcAccessMode::Free
    }

    pub fn authorize(
        &self,
        request: &RpcRequest,
        authorization: Option<&RpcAccessAuthorization>,
        now: u64,
    ) -> Result<AccessCharge, RpcAccessError> {
        if matches!(request, RpcRequest::Status) || self.is_free() {
            return Ok(AccessCharge::free());
        }
        let authorization = authorization.ok_or(RpcAccessError::AuthorizationRequired)?;
        let grant = authorization.grant();
        let grant_terms = grant.terms();
        if now < grant.valid_from()
            || now > grant.valid_until()
            || grant.valid_from() > grant_terms.quote_valid_until()
        {
            return Err(RpcAccessError::Expired);
        }
        if verify_terms(grant_terms).is_err() {
            return Err(RpcAccessError::InvalidGrant);
        }
        if grant.chain_id() != self.terms.chain_id()
            || grant.operator_id() != self.terms.operator_id()
            || grant_terms.operator_public_key() != self.terms.operator_public_key()
            || grant
                .valid_until()
                .checked_sub(grant.valid_from())
                .is_none_or(|duration| duration > grant_terms.maximum_grant_lifetime())
            || (grant_terms.mode() == RpcAccessMode::Allowlist && grant.paid_amount() != 0)
            || (grant_terms.mode() == RpcAccessMode::Prepaid
                && grant_terms
                    .unit_price()
                    .checked_mul(u128::from(grant.purchased_units()))
                    .is_none_or(|minimum| grant.paid_amount() < minimum))
            || activechain_consensus_verifier::verify_ml_dsa44(
                self.terms.operator_public_key(),
                &grant.signing_payload(),
                grant.operator_signature().as_bytes(),
            )
            .is_err()
        {
            return Err(RpcAccessError::InvalidGrant);
        }
        let request_commitment = RpcAccessRequest::request_commitment(request)
            .map_err(|_| RpcAccessError::InvalidGrant)?;
        if authorization.request_commitment() != request_commitment
            || activechain_consensus_verifier::verify_ml_dsa44(
                grant.client_public_key(),
                &authorization.signing_payload(),
                authorization.client_signature().as_bytes(),
            )
            .is_err()
        {
            return Err(RpcAccessError::InvalidGrant);
        }
        let cost = grant_terms.cost(request).ok_or(RpcAccessError::BudgetExhausted)?;
        let mut usage = self.usage.lock().map_err(|_| RpcAccessError::Persistence)?;
        let mut next = usage.clone();
        let position =
            next.records.binary_search_by_key(&grant.grant_id(), |record| record.grant_id);
        let (index, spent_units) = match position {
            Ok(index) => {
                let record = next.records[index];
                if authorization.sequence() != record.next_sequence {
                    return Err(RpcAccessError::Replay);
                }
                (index, record.spent_units)
            }
            Err(index) => {
                if authorization.sequence() != 0 || next.records.len() == MAX_USAGE_RECORDS {
                    return Err(RpcAccessError::Replay);
                }
                next.records.insert(
                    index,
                    UsageRecord { grant_id: grant.grant_id(), next_sequence: 0, spent_units: 0 },
                );
                (index, 0)
            }
        };
        let new_spent = spent_units.checked_add(cost).ok_or(RpcAccessError::BudgetExhausted)?;
        if new_spent > grant.purchased_units() {
            return Err(RpcAccessError::BudgetExhausted);
        }
        next.records[index].spent_units = new_spent;
        next.records[index].next_sequence =
            authorization.sequence().checked_add(1).ok_or(RpcAccessError::BudgetExhausted)?;
        let path = self.usage_path.as_ref().ok_or(RpcAccessError::Persistence)?;
        save_usage(path, &next)?;
        *usage = next;
        Ok(AccessCharge {
            charged_units: cost,
            remaining_units: Some(grant.purchased_units() - new_spent),
        })
    }
}

fn verify_terms(terms: &RpcAccessTerms) -> Result<(), RpcAccessError> {
    let signature = terms.operator_signature().ok_or(RpcAccessError::InvalidGrant)?;
    activechain_consensus_verifier::verify_ml_dsa44(
        terms.operator_public_key(),
        &terms.signing_payload(),
        signature.as_bytes(),
    )
    .map_err(|_| RpcAccessError::InvalidGrant)
}

fn access_scope(terms: &RpcAccessTerms) -> Digest384 {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-RPC-ACCESS-SCOPE-V1");
    hasher.update(terms.chain_id().digest().as_bytes());
    hasher.update(terms.operator_id().as_bytes());
    hasher.update(terms.operator_public_key());
    let mut output = [0; 48];
    hasher.finalize_xof().read(&mut output);
    Digest384::new(output)
}

fn save_usage(path: &Path, state: &UsageState) -> Result<(), RpcAccessError> {
    let bytes = encode_envelope(state).map_err(|_| RpcAccessError::Persistence)?;
    let tag = snapshot_tag(&bytes);
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary).map_err(|_| RpcAccessError::Persistence)?;
    file.write_all(&bytes).map_err(|_| RpcAccessError::Persistence)?;
    file.write_all(&tag).map_err(|_| RpcAccessError::Persistence)?;
    file.sync_all().map_err(|_| RpcAccessError::Persistence)?;
    std::fs::rename(&temporary, path).map_err(|_| RpcAccessError::Persistence)?;
    let parent =
        path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RpcAccessError::Persistence)
}
fn load_usage(path: &Path) -> Result<UsageState, RpcAccessError> {
    let length = std::fs::metadata(path).map_err(|_| RpcAccessError::Persistence)?.len();
    if length < 32 || length > (UsageState::MAX_ENCODED_LEN + 40) as u64 {
        return Err(RpcAccessError::Persistence);
    }
    let bytes = std::fs::read(path).map_err(|_| RpcAccessError::Persistence)?;
    if bytes.len() < 32 {
        return Err(RpcAccessError::Persistence);
    }
    let body = bytes.len() - 32;
    if snapshot_tag(&bytes[..body]) != bytes[body..] {
        return Err(RpcAccessError::Persistence);
    }
    decode_envelope(&bytes[..body]).map_err(|_| RpcAccessError::Persistence)
}
fn snapshot_tag(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"ACTIVECHAIN-RPC-ACCESS-USAGE-SNAPSHOT-V1");
    hasher.update(bytes);
    let mut output = [0; 32];
    hasher.finalize_xof().read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use activechain_protocol_types::{ChainId, CryptoSuiteId, ProtocolSignature};
    use activechain_rpc_types::{
        ProofKind, QueryKind, RpcAccessGrant, RpcAccessMode, RpcAccessResponse, RpcAccessTerms,
        RpcError, RpcResponse,
    };
    use ml_dsa::{Keypair, MlDsa44, Seed, Signer, SigningKey};
    use std::{net::TcpListener, sync::Arc, thread};

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }
    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "activechain-rpc-access-{name}-{}-{}.snapshot",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }
    fn terms(operator: &SigningKey<MlDsa44>, mode: RpcAccessMode) -> RpcAccessTerms {
        priced_terms(operator, mode, if mode == RpcAccessMode::Prepaid { 3 } else { 0 }, 2)
    }
    fn priced_terms(
        operator: &SigningKey<MlDsa44>,
        mode: RpcAccessMode,
        unit_price: u128,
        get_units: u64,
    ) -> RpcAccessTerms {
        priced_terms_for_chain(operator, ChainId::new(digest(1)), mode, unit_price, get_units)
    }
    fn priced_terms_for_chain(
        operator: &SigningKey<MlDsa44>,
        chain_id: ChainId,
        mode: RpcAccessMode,
        unit_price: u128,
        get_units: u64,
    ) -> RpcAccessTerms {
        let draft = RpcAccessTerms::new(
            chain_id,
            digest(2),
            mode,
            if mode == RpcAccessMode::Free {
                Vec::new()
            } else {
                operator.verifying_key().encode().to_vec()
            },
            unit_price,
            if mode == RpcAccessMode::Prepaid { digest(3) } else { Digest384::ZERO },
            if mode == RpcAccessMode::Prepaid { digest(4) } else { Digest384::ZERO },
            get_units,
            1,
            1,
            100,
            50,
            None,
        )
        .unwrap();
        if mode == RpcAccessMode::Free {
            return draft;
        }
        let signature = operator.sign(&draft.signing_payload());
        draft
            .with_operator_signature(
                ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec())
                    .unwrap(),
            )
            .unwrap()
    }
    #[allow(clippy::too_many_arguments)]
    fn signed_grant(
        operator: &SigningKey<MlDsa44>,
        client: &SigningKey<MlDsa44>,
        terms: &RpcAccessTerms,
        grant_id: Digest384,
        valid_from: u64,
        valid_until: u64,
        units: u64,
        paid: u128,
    ) -> RpcAccessGrant {
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap();
        let unsigned = RpcAccessGrant::new(
            terms.clone(),
            grant_id,
            client.verifying_key().encode().to_vec(),
            valid_from,
            valid_until,
            units,
            paid,
            digest(9),
            placeholder,
        )
        .unwrap();
        let signature = operator.sign(&unsigned.signing_payload());
        RpcAccessGrant::new(
            unsigned.terms().clone(),
            unsigned.grant_id(),
            unsigned.client_public_key().to_vec(),
            unsigned.valid_from(),
            unsigned.valid_until(),
            unsigned.purchased_units(),
            unsigned.paid_amount(),
            unsigned.settlement_reference(),
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap()
    }
    fn authorization(
        client: &SigningKey<MlDsa44>,
        grant: RpcAccessGrant,
        request: &RpcRequest,
        sequence: u64,
    ) -> RpcAccessAuthorization {
        let commitment = RpcAccessRequest::request_commitment(request).unwrap();
        let placeholder = ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, vec![0; 2_420]).unwrap();
        let unsigned =
            RpcAccessAuthorization::new(grant, sequence, commitment, placeholder).unwrap();
        let signature = client.sign(&unsigned.signing_payload());
        RpcAccessAuthorization::new(
            unsigned.grant().clone(),
            sequence,
            commitment,
            ProtocolSignature::new(CryptoSuiteId::ML_DSA_44, signature.encode().to_vec()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn free_mode_needs_no_identity_or_usage_state() {
        let operator = SigningKey::<MlDsa44>::from_seed(&Seed::from([1; 32]));
        let controller = RpcAccessController::free(terms(&operator, RpcAccessMode::Free)).unwrap();
        let request = RpcRequest::Get { kind: QueryKind::State, key: digest(10) };
        assert_eq!(controller.authorize(&request, None, 5), Ok(AccessCharge::free()));
        assert!(controller.is_free());
    }

    #[test]
    fn allowlist_mode_uses_zero_price_authenticated_grants() {
        let operator = SigningKey::<MlDsa44>::from_seed(&Seed::from([7; 32]));
        let client = SigningKey::<MlDsa44>::from_seed(&Seed::from([8; 32]));
        let terms = terms(&operator, RpcAccessMode::Allowlist);
        assert_eq!(verify_access_terms(&terms, ChainId::new(digest(1)), digest(2), 100), Ok(()));
        assert_eq!(
            verify_access_terms(&terms, ChainId::new(digest(1)), digest(2), 101),
            Err(RpcAccessError::InvalidGrant)
        );
        assert_eq!(
            verify_access_terms(&terms, ChainId::new(digest(99)), digest(2), 100),
            Err(RpcAccessError::InvalidGrant)
        );
        let usage_path = path("allowlist");
        let _ = std::fs::remove_file(&usage_path);
        let controller = RpcAccessController::create(terms.clone(), usage_path.clone()).unwrap();
        let grant = signed_grant(&operator, &client, &terms, digest(30), 1, 10, 2, 0);
        let request = RpcRequest::Get { kind: QueryKind::State, key: digest(31) };
        let authorization = authorization(&client, grant, &request, 0);
        assert_eq!(
            controller.authorize(&request, Some(&authorization), 1),
            Ok(AccessCharge { charged_units: 2, remaining_units: Some(0) })
        );
        let _ = std::fs::remove_file(usage_path);
    }

    #[test]
    fn prepaid_network_request_is_metered_before_query_response() {
        let operator = SigningKey::<MlDsa44>::from_seed(&Seed::from([9; 32]));
        let client = SigningKey::<MlDsa44>::from_seed(&Seed::from([10; 32]));
        let terms = terms(&operator, RpcAccessMode::Prepaid);
        let usage_path = path("network-usage");
        let index_path = path("network-index");
        let _ = std::fs::remove_file(&usage_path);
        let _ = std::fs::remove_file(&index_path);
        let controller =
            Arc::new(RpcAccessController::create(terms.clone(), usage_path.clone()).unwrap());
        let index = crate::RpcIndex::new(
            terms.chain_id(),
            digest(40),
            1,
            0,
            1,
            10,
            vec![ProofKind::FinalityCertificate],
            vec![],
        )
        .unwrap();
        let store = Arc::new(crate::DurableRpcStore::create(index_path.clone(), index).unwrap());
        let request = RpcRequest::Get { kind: QueryKind::State, key: digest(41) };
        let grant = signed_grant(&operator, &client, &terms, digest(42), 1, 20, 5, 15);
        let authorization = authorization(&client, grant, &request, 0);
        let wire =
            RpcAccessRequest::Execute { request, authorization: Some(Box::new(authorization)) };
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = crate::RpcServer::with_access(store.clone(), controller.clone()).unwrap();
        let worker = thread::spawn(move || server.serve_once(&listener, 2));
        assert_eq!(
            crate::query_with_access(address, &wire).unwrap(),
            RpcAccessResponse::Response {
                response: RpcResponse::Error(RpcError::NotFound),
                charged_units: 2,
                remaining_units: Some(3),
            }
        );
        worker.join().unwrap().unwrap();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = crate::RpcServer::with_access(store, controller).unwrap();
        let worker = thread::spawn(move || server.serve_once(&listener, 2));
        assert!(matches!(
            crate::query(address, &RpcRequest::Status).unwrap(),
            RpcResponse::Status(_)
        ));
        worker.join().unwrap().unwrap();
        let _ = std::fs::remove_file(usage_path);
        let _ = std::fs::remove_file(index_path);
    }

    #[test]
    fn prepaid_grants_are_pq_bound_metered_durable_and_replay_safe() {
        let operator = SigningKey::<MlDsa44>::from_seed(&Seed::from([2; 32]));
        let client = SigningKey::<MlDsa44>::from_seed(&Seed::from([3; 32]));
        let terms = terms(&operator, RpcAccessMode::Prepaid);
        let usage_path = path("metering");
        let _ = std::fs::remove_file(&usage_path);
        let controller = RpcAccessController::create(terms.clone(), usage_path.clone()).unwrap();
        let grant = signed_grant(&operator, &client, &terms, digest(11), 10, 30, 5, 15);
        let get = RpcRequest::Get { kind: QueryKind::Receipt, key: digest(12) };
        let first = authorization(&client, grant.clone(), &get, 0);
        assert_eq!(
            controller.authorize(&get, Some(&first), 10),
            Ok(AccessCharge { charged_units: 2, remaining_units: Some(3) })
        );
        assert_eq!(controller.authorize(&get, Some(&first), 10), Err(RpcAccessError::Replay));
        drop(controller);

        let controller = RpcAccessController::load(terms.clone(), usage_path.clone()).unwrap();
        let second = authorization(&client, grant.clone(), &get, 1);
        assert_eq!(
            controller.authorize(&get, Some(&second), 11),
            Ok(AccessCharge { charged_units: 2, remaining_units: Some(1) })
        );
        drop(controller);
        let repriced = priced_terms(&operator, RpcAccessMode::Prepaid, 9, 1);
        let controller = RpcAccessController::load(repriced, usage_path.clone()).unwrap();
        let third = authorization(&client, grant, &get, 2);
        assert_eq!(
            controller.authorize(&get, Some(&third), 11),
            Err(RpcAccessError::BudgetExhausted),
            "the embedded old offer keeps its two-unit request cost after repricing"
        );

        let mut corrupt = std::fs::read(&usage_path).unwrap();
        corrupt[7] ^= 1;
        std::fs::write(&usage_path, corrupt).unwrap();
        assert!(matches!(
            RpcAccessController::load(terms, usage_path.clone()),
            Err(RpcAccessError::Persistence)
        ));
        let _ = std::fs::remove_file(usage_path);
    }

    #[test]
    fn invalid_context_expiry_signature_and_failed_publish_do_not_consume_sequence() {
        let operator = SigningKey::<MlDsa44>::from_seed(&Seed::from([4; 32]));
        let client = SigningKey::<MlDsa44>::from_seed(&Seed::from([5; 32]));
        let impostor = SigningKey::<MlDsa44>::from_seed(&Seed::from([6; 32]));
        let terms = terms(&operator, RpcAccessMode::Prepaid);
        let usage_path = path("atomic");
        let _ = std::fs::remove_file(&usage_path);
        let mut controller =
            RpcAccessController::create(terms.clone(), usage_path.clone()).unwrap();
        let grant = signed_grant(&operator, &client, &terms, digest(20), 10, 20, 10, 30);
        let request = RpcRequest::List { kind: QueryKind::Action, after: None, limit: 2 };
        let wrong_client = authorization(&impostor, grant.clone(), &request, 0);
        assert_eq!(
            controller.authorize(&request, Some(&wrong_client), 10),
            Err(RpcAccessError::InvalidGrant)
        );
        let forged_grant = signed_grant(&impostor, &client, &terms, digest(21), 10, 20, 10, 30);
        let forged = authorization(&client, forged_grant, &request, 0);
        assert_eq!(
            controller.authorize(&request, Some(&forged), 10),
            Err(RpcAccessError::InvalidGrant)
        );
        let valid = authorization(&client, grant, &request, 0);
        let substituted_request = RpcRequest::Get { kind: QueryKind::Action, key: digest(22) };
        assert_eq!(
            controller.authorize(&substituted_request, Some(&valid), 10),
            Err(RpcAccessError::InvalidGrant)
        );
        let wrong_chain_terms = priced_terms_for_chain(
            &operator,
            ChainId::new(digest(99)),
            RpcAccessMode::Prepaid,
            3,
            2,
        );
        let wrong_chain_grant =
            signed_grant(&operator, &client, &wrong_chain_terms, digest(23), 10, 20, 10, 30);
        let wrong_chain = authorization(&client, wrong_chain_grant, &request, 0);
        assert_eq!(
            controller.authorize(&request, Some(&wrong_chain), 10),
            Err(RpcAccessError::InvalidGrant)
        );
        assert_eq!(controller.authorize(&request, Some(&valid), 21), Err(RpcAccessError::Expired));
        let original_path = controller.usage_path.clone();
        controller.usage_path = Some(path("missing-parent").join("usage"));
        assert_eq!(
            controller.authorize(&request, Some(&valid), 10),
            Err(RpcAccessError::Persistence)
        );
        controller.usage_path = original_path;
        assert_eq!(
            controller.authorize(&request, Some(&valid), 10),
            Ok(AccessCharge { charged_units: 3, remaining_units: Some(7) })
        );
        let _ = std::fs::remove_file(usage_path);
    }
}
