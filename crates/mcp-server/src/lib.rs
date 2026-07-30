#![forbid(unsafe_code)]

//! Stable MCP 2025-11-25 lifecycle and read-only ActiveChain tools.

use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use activechain_canonical_codec::{CanonicalDecode, CanonicalEncode, Decoder, Encoder};
use activechain_proposal_gateway::{
    AnchorProposalArgumentsV1, AuthenticatedProposalContext, ProposalJournalV1,
    TransferProposalArgumentsV1,
};
use activechain_protocol_types::Digest384;
use activechain_rpc_server::{DurableRpcStore, verify_query_record};
use activechain_rpc_types::{Health, QueryKind, QueryRecord, RpcRequest, RpcResponse};
use serde::Deserialize;
use serde_json::{Value, json};

pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
pub const SERVER_NAME: &str = "activechain-read-only";
pub const MAX_MCP_LINE_BYTES: usize = activechain_agent_interfaces::MAX_FRAME_BYTES;
pub const MAX_REQUESTS_PER_SESSION: usize = 4_096;
const MAX_QUERY_RECORD_BYTES: usize =
    1 + 48 + 8 + 3 * (4 + activechain_rpc_types::MAX_RPC_BLOB_LENGTH);

const TOOLS: [&str; 7] = [
    "activechain_get_pending_approvals",
    "activechain_get_status",
    "activechain_list_assets",
    "activechain_propose_transfer",
    "activechain_resolve_receipt",
    "activechain_submit_anchor_proposal",
    "activechain_verify_record",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendError {
    InvalidArguments,
    NotFound,
    Stale,
    VerificationFailed,
    Unavailable,
}

pub trait ReadOnlyBackend {
    fn get_status(&self) -> Result<Value, BackendError>;
    fn list_assets(&self, after: Option<&str>, limit: u16) -> Result<Value, BackendError>;
    fn verify_record(&self, record: &str) -> Result<Value, BackendError>;
    fn get_pending_approvals(&self, limit: u16) -> Result<Value, BackendError>;
    fn resolve_receipt(&self, key: &str) -> Result<Value, BackendError>;
    fn propose_transfer(&self, _arguments: &Value) -> Result<Value, BackendError> {
        Err(BackendError::Unavailable)
    }
    fn propose_anchor(&self, _arguments: &Value) -> Result<Value, BackendError> {
        Err(BackendError::Unavailable)
    }
}

pub struct ProposalBackend<B> {
    observations: B,
    journal: Mutex<ProposalJournalV1>,
    context: AuthenticatedProposalContext,
    journal_path: PathBuf,
    height: fn() -> u64,
}

impl<B> ProposalBackend<B> {
    #[must_use]
    pub fn new(
        observations: B,
        journal: ProposalJournalV1,
        context: AuthenticatedProposalContext,
        journal_path: PathBuf,
        height: fn() -> u64,
    ) -> Self {
        Self { observations, journal: Mutex::new(journal), context, journal_path, height }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalToolArguments {
    request_id: String,
    authority: activechain_agent_interfaces::AuthorityBindingV1,
    transfer: TransferProposalArgumentsV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorProposalToolArguments {
    request_id: String,
    authority: activechain_agent_interfaces::AuthorityBindingV1,
    anchor: AnchorProposalArgumentsV1,
}

impl<B: ReadOnlyBackend> ReadOnlyBackend for ProposalBackend<B> {
    fn get_status(&self) -> Result<Value, BackendError> {
        self.observations.get_status()
    }
    fn list_assets(&self, after: Option<&str>, limit: u16) -> Result<Value, BackendError> {
        self.observations.list_assets(after, limit)
    }
    fn verify_record(&self, record: &str) -> Result<Value, BackendError> {
        self.observations.verify_record(record)
    }
    fn get_pending_approvals(&self, limit: u16) -> Result<Value, BackendError> {
        self.observations.get_pending_approvals(limit)
    }
    fn resolve_receipt(&self, key: &str) -> Result<Value, BackendError> {
        self.observations.resolve_receipt(key)
    }
    fn propose_transfer(&self, arguments: &Value) -> Result<Value, BackendError> {
        let request: ProposalToolArguments = serde_json::from_value(arguments.clone())
            .map_err(|_| BackendError::InvalidArguments)?;
        let mut journal = self.journal.lock().map_err(|_| BackendError::Unavailable)?;
        let (receipt, audit) = journal
            .propose_transfer_durable(
                &request.request_id,
                &request.authority,
                &request.transfer,
                &self.context,
                (self.height)(),
                &self.journal_path,
            )
            .map_err(map_gateway_error)?;
        Ok(json!({
            "proposal_id": hex(receipt.proposal_id.as_bytes()),
            "intent_commitment": hex(receipt.intent_commitment.as_bytes()),
            "approval_state": match receipt.approval {
                activechain_proposal_gateway::ApprovalRequirement::NativeWalletReview => "native_wallet_review",
                activechain_proposal_gateway::ApprovalRequirement::NativeWalletReviewWithWarning => "native_wallet_review_with_warning",
            },
            "duplicate": receipt.duplicate,
            "audit": { "proposal_id": hex(audit.proposal_id.as_bytes()), "action": "transfer", "duplicate": audit.duplicate }
        }))
    }

    fn propose_anchor(&self, arguments: &Value) -> Result<Value, BackendError> {
        let request: AnchorProposalToolArguments = serde_json::from_value(arguments.clone())
            .map_err(|_| BackendError::InvalidArguments)?;
        let mut journal = self.journal.lock().map_err(|_| BackendError::Unavailable)?;
        let (receipt, audit) = journal
            .propose_anchor_durable(
                &request.request_id,
                &request.authority,
                &request.anchor,
                &self.context,
                (self.height)(),
                &self.journal_path,
            )
            .map_err(map_gateway_error)?;
        Ok(json!({
            "proposal_id": hex(receipt.proposal_id.as_bytes()),
            "intent_commitment": hex(receipt.intent_commitment.as_bytes()),
            "approval_state": "native_wallet_review",
            "duplicate": receipt.duplicate,
            "audit": { "proposal_id": hex(audit.proposal_id.as_bytes()), "action": "submit_anchor", "duplicate": audit.duplicate }
        }))
    }
}

pub struct StoreBackend {
    store: Arc<DurableRpcStore>,
    now: fn() -> u64,
}

impl StoreBackend {
    #[must_use]
    pub const fn new(store: Arc<DurableRpcStore>, now: fn() -> u64) -> Self {
        Self { store, now }
    }

    fn status_response(&self) -> Result<activechain_rpc_types::RpcStatus, BackendError> {
        match self.store.handle(RpcRequest::Status, (self.now)()) {
            RpcResponse::Status(status) => Ok(status),
            _ => Err(BackendError::Unavailable),
        }
    }

    fn record_json(record: &QueryRecord) -> Result<Value, BackendError> {
        verify_query_record(record).map_err(|_| BackendError::VerificationFailed)?;
        let mut encoder = Encoder::new(MAX_QUERY_RECORD_BYTES);
        record.encode(&mut encoder).map_err(|_| BackendError::Unavailable)?;
        let envelope = encoder.finish();
        Ok(json!({
            "kind": query_kind_name(record.kind()),
            "key": hex(record.key().as_bytes()),
            "finalized_height": record.finalized_height(),
            "verified": true,
            "record_envelope": hex(&envelope),
        }))
    }
}

impl ReadOnlyBackend for StoreBackend {
    fn get_status(&self) -> Result<Value, BackendError> {
        let status = self.status_response()?;
        Ok(json!({
            "chain_id": hex(status.chain_id().digest().as_bytes()),
            "genesis_commitment": hex(status.genesis_commitment().as_bytes()),
            "network_identity": hex(status.identity_commitment().as_bytes()),
            "protocol_revision": status.protocol_revision(),
            "rpc_schema_revision": status.rpc_schema_revision(),
            "finalized_height": status.finalized_height(),
            "maximum_staleness_seconds": status.maximum_staleness_seconds(),
            "health": match status.health() { Health::Healthy => "healthy", Health::Stale => "stale", Health::Degraded => "degraded" },
        }))
    }

    fn list_assets(&self, after: Option<&str>, limit: u16) -> Result<Value, BackendError> {
        if limit == 0 || limit > activechain_rpc_types::MAX_RPC_PAGE_SIZE {
            return Err(BackendError::InvalidArguments);
        }
        let after = after.map(parse_digest).transpose()?;
        match self.store.handle(
            RpcRequest::List { kind: QueryKind::FungibleCoinCell, after, limit },
            (self.now)(),
        ) {
            RpcResponse::Page(page) => {
                let records =
                    page.records().iter().map(Self::record_json).collect::<Result<Vec<_>, _>>()?;
                Ok(json!({
                    "records": records,
                    "next_cursor": page.next().map(|value| hex(value.as_bytes())),
                    "verified": true,
                }))
            }
            RpcResponse::Error(activechain_rpc_types::RpcError::Stale) => Err(BackendError::Stale),
            _ => Err(BackendError::Unavailable),
        }
    }

    fn verify_record(&self, record: &str) -> Result<Value, BackendError> {
        let bytes = decode_hex(record, MAX_QUERY_RECORD_BYTES)?;
        let mut decoder = Decoder::new(&bytes);
        let record =
            QueryRecord::decode(&mut decoder).map_err(|_| BackendError::InvalidArguments)?;
        decoder.finish().map_err(|_| BackendError::InvalidArguments)?;
        Self::record_json(&record)
    }

    fn get_pending_approvals(&self, _limit: u16) -> Result<Value, BackendError> {
        // Pending approvals are wallet-local and deliberately unavailable from
        // a node-only backend. A wallet backend may implement this trait.
        Err(BackendError::Unavailable)
    }

    fn resolve_receipt(&self, key: &str) -> Result<Value, BackendError> {
        let key = parse_digest(key)?;
        match self
            .store
            .handle(RpcRequest::Get { kind: QueryKind::ApplicationReceipt, key }, (self.now)())
        {
            RpcResponse::Record(record) => Self::record_json(&record),
            RpcResponse::Error(activechain_rpc_types::RpcError::NotFound) => {
                Err(BackendError::NotFound)
            }
            RpcResponse::Error(activechain_rpc_types::RpcError::Stale) => Err(BackendError::Stale),
            _ => Err(BackendError::Unavailable),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

pub struct McpSession<B> {
    backend: B,
    initialized: bool,
    ready: bool,
    request_ids: BTreeSet<String>,
}

impl<B: ReadOnlyBackend> McpSession<B> {
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self { backend, initialized: false, ready: false, request_ids: BTreeSet::new() }
    }

    pub fn handle_line(&mut self, line: &[u8]) -> Option<Vec<u8>> {
        if line.is_empty() || line.len() > MAX_MCP_LINE_BYTES || line.contains(&b'\n') {
            return Some(error_response(Value::Null, -32700, "Invalid bounded JSON-RPC frame"));
        }
        let raw: Value = match serde_json::from_slice(line) {
            Ok(raw) => raw,
            Err(_) => return Some(error_response(Value::Null, -32700, "Malformed JSON")),
        };
        if raw.get("id").is_none() {
            self.handle_notification(&raw);
            return None;
        }
        let request: JsonRpcRequest = match serde_json::from_value(raw) {
            Ok(request) => request,
            Err(_) => return Some(error_response(Value::Null, -32600, "Invalid request")),
        };
        let id = request.id.clone();
        if request.jsonrpc != "2.0" || !valid_request_id(&id) {
            return Some(error_response(id, -32600, "Invalid request"));
        }
        let key = id.to_string();
        if self.request_ids.len() >= MAX_REQUESTS_PER_SESSION || !self.request_ids.insert(key) {
            return Some(error_response(id, -32600, "Request ID reused or session limit reached"));
        }
        let result = match request.method.as_str() {
            "initialize" => self.initialize(&request.params),
            "ping" => Ok(json!({})),
            "tools/list" if self.ready => Ok(tool_list()),
            "tools/call" if self.ready => self.call_tool(&request.params),
            "tools/list" | "tools/call" => Err((-32002, "Server is not initialized")),
            _ => Err((-32601, "Method not found")),
        };
        Some(match result {
            Ok(result) => success_response(id, result),
            Err((code, message)) => error_response(id, code, message),
        })
    }

    fn initialize(&mut self, params: &Value) -> Result<Value, (i64, &'static str)> {
        if self.initialized
            || params.get("protocolVersion").and_then(Value::as_str) != Some(MCP_PROTOCOL_VERSION)
        {
            return Err((-32602, "Unsupported protocol version or repeated initialization"));
        }
        self.initialized = true;
        Ok(json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
            "instructions": "Read-only proof-bearing ActiveChain access. Tool results are verified locally; MCP never confers authority."
        }))
    }

    fn handle_notification(&mut self, raw: &Value) {
        if raw.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && raw.get("method").and_then(Value::as_str) == Some("notifications/initialized")
            && self.initialized
        {
            self.ready = true;
        }
    }

    fn call_tool(&self, params: &Value) -> Result<Value, (i64, &'static str)> {
        let name =
            params.get("name").and_then(Value::as_str).ok_or((-32602, "Invalid tool arguments"))?;
        if !TOOLS.contains(&name) {
            return Err((-32602, "Unknown tool"));
        }
        let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
        if !arguments.is_object() {
            return Err((-32602, "Invalid tool arguments"));
        }
        let allowed = match name {
            "activechain_get_status" => &[][..],
            "activechain_list_assets" => &["after", "limit"][..],
            "activechain_propose_transfer" => &["request_id", "authority", "transfer"][..],
            "activechain_submit_anchor_proposal" => &["request_id", "authority", "anchor"][..],
            "activechain_verify_record" => &["record"][..],
            "activechain_get_pending_approvals" => &["limit"][..],
            "activechain_resolve_receipt" => &["key"][..],
            _ => unreachable!(),
        };
        if !has_only_keys(&arguments, allowed) {
            return Err((-32602, "Invalid tool arguments"));
        }
        let output = match name {
            "activechain_get_status" => self.backend.get_status(),
            "activechain_list_assets" => self.backend.list_assets(
                arguments.get("after").and_then(Value::as_str),
                bounded_limit(&arguments)?,
            ),
            "activechain_propose_transfer" => self.backend.propose_transfer(&arguments),
            "activechain_submit_anchor_proposal" => self.backend.propose_anchor(&arguments),
            "activechain_verify_record" => {
                self.backend.verify_record(required_string(&arguments, "record")?)
            }
            "activechain_get_pending_approvals" => {
                self.backend.get_pending_approvals(bounded_limit(&arguments)?)
            }
            "activechain_resolve_receipt" => {
                self.backend.resolve_receipt(required_string(&arguments, "key")?)
            }
            _ => unreachable!(),
        };
        match output {
            Ok(value) => Ok(tool_result(value, false)),
            Err(error) => Ok(tool_result(json!({ "error": backend_error_name(error) }), true)),
        }
    }
}

fn tool_list() -> Value {
    json!({ "tools": [
        tool("activechain_get_pending_approvals", "List bounded wallet-local pending approvals when a wallet backend is installed", json!({"type":"object","additionalProperties":false,"properties":{"limit":{"type":"integer","minimum":1,"maximum":4}}})),
        tool("activechain_get_status", "Return ActiveChain network identity, finalized height, and health", empty_schema()),
        tool("activechain_list_assets", "List a bounded page of verified finalized fungible asset records", json!({"type":"object","additionalProperties":false,"properties":{"after":{"type":"string","pattern":"^[A-Fa-f0-9]{96}$"},"limit":{"type":"integer","minimum":1,"maximum":4}}})),
        proposal_tool(),
        anchor_proposal_tool(),
        tool("activechain_resolve_receipt", "Resolve and verify a finalized application receipt", json!({"type":"object","additionalProperties":false,"required":["key"],"properties":{"key":{"type":"string","pattern":"^[A-Fa-f0-9]{96}$"}}})),
        tool("activechain_verify_record", "Verify a canonical proof-bearing query record locally", json!({"type":"object","additionalProperties":false,"required":["record"],"properties":{"record":{"type":"string","maxLength":524304,"pattern":"^[A-Fa-f0-9]+$"}}})),
    ] })
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": { "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
    })
}

fn proposal_tool() -> Value {
    json!({
        "name": "activechain_propose_transfer",
        "description": "Persist an exact transfer proposal for later native-wallet review; never signs or submits",
        "inputSchema": {
            "type": "object", "additionalProperties": false,
            "required": ["request_id", "authority", "transfer"],
            "properties": {
                "request_id": {"type":"string","minLength":1,"maxLength":128},
                "authority": {"type":"object"},
                "transfer": {"type":"object"}
            }
        },
        "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
    })
}

fn anchor_proposal_tool() -> Value {
    json!({
        "name": "activechain_submit_anchor_proposal",
        "description": "Persist an exact digest-anchor proposal for later native-wallet review; never submits it",
        "inputSchema": {
            "type": "object", "additionalProperties": false,
            "required": ["request_id", "authority", "anchor"],
            "properties": {
                "request_id": {"type":"string","minLength":1,"maxLength":128},
                "authority": {"type":"object"},
                "anchor": {"type":"object"}
            }
        },
        "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
    })
}

fn empty_schema() -> Value {
    json!({"type":"object","additionalProperties":false})
}

fn tool_result(value: Value, is_error: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string(&value).unwrap_or_else(|_| "{}".into()) }],
        "structuredContent": value,
        "isError": is_error
    })
}

fn success_response(id: Value, result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": result }))
        .expect("JSON response")
}

fn error_response(id: Value, code: i64, message: &str) -> Vec<u8> {
    serde_json::to_vec(
        &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    )
    .expect("JSON response")
}

fn valid_request_id(id: &Value) -> bool {
    matches!(id, Value::String(value) if !value.is_empty() && value.len() <= 128)
        || matches!(id, Value::Number(value) if value.is_i64() || value.is_u64())
}

fn bounded_limit(arguments: &Value) -> Result<u16, (i64, &'static str)> {
    let limit = arguments.get("limit").and_then(Value::as_u64).unwrap_or(4);
    u16::try_from(limit)
        .ok()
        .filter(|limit| *limit > 0 && *limit <= activechain_rpc_types::MAX_RPC_PAGE_SIZE)
        .ok_or((-32602, "Invalid tool arguments"))
}

fn required_string<'a>(arguments: &'a Value, key: &str) -> Result<&'a str, (i64, &'static str)> {
    arguments.get(key).and_then(Value::as_str).ok_or((-32602, "Invalid tool arguments"))
}

fn has_only_keys(arguments: &Value, allowed: &[&str]) -> bool {
    arguments
        .as_object()
        .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str())))
}

fn parse_digest(value: &str) -> Result<Digest384, BackendError> {
    let bytes = decode_hex(value, 48)?;
    let bytes: [u8; 48] = bytes.try_into().map_err(|_| BackendError::InvalidArguments)?;
    Ok(Digest384::new(bytes))
}

fn decode_hex(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, BackendError> {
    if value.is_empty() || !value.len().is_multiple_of(2) || value.len() / 2 > maximum_bytes {
        return Err(BackendError::InvalidArguments);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, BackendError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(BackendError::InvalidArguments),
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn query_kind_name(kind: QueryKind) -> &'static str {
    match kind {
        QueryKind::State => "state",
        QueryKind::Action => "action",
        QueryKind::Receipt => "receipt",
        QueryKind::ApplicationReceipt => "application_receipt",
        QueryKind::CoinCell => "coin_cell",
        QueryKind::FungibleCoinCell => "fungible_coin_cell",
        QueryKind::NonFungibleCoinCell => "non_fungible_coin_cell",
    }
}

fn backend_error_name(error: BackendError) -> &'static str {
    match error {
        BackendError::InvalidArguments => "invalid_arguments",
        BackendError::NotFound => "not_found",
        BackendError::Stale => "stale",
        BackendError::VerificationFailed => "verification_failed",
        BackendError::Unavailable => "unavailable",
    }
}

fn map_gateway_error(error: activechain_proposal_gateway::GatewayError) -> BackendError {
    match error {
        activechain_proposal_gateway::GatewayError::InvalidArguments => {
            BackendError::InvalidArguments
        }
        activechain_proposal_gateway::GatewayError::Expired
        | activechain_proposal_gateway::GatewayError::InvalidAuthority
        | activechain_proposal_gateway::GatewayError::PolicyDenied
        | activechain_proposal_gateway::GatewayError::BudgetExceeded
        | activechain_proposal_gateway::GatewayError::ReplayConflict => {
            BackendError::VerificationFailed
        }
        activechain_proposal_gateway::GatewayError::Capacity
        | activechain_proposal_gateway::GatewayError::Persistence => BackendError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureBackend;
    impl ReadOnlyBackend for FixtureBackend {
        fn get_status(&self) -> Result<Value, BackendError> {
            Ok(json!({"verified":true,"height":7}))
        }
        fn list_assets(&self, _: Option<&str>, limit: u16) -> Result<Value, BackendError> {
            Ok(json!({"verified":true,"limit":limit}))
        }
        fn verify_record(&self, _: &str) -> Result<Value, BackendError> {
            Err(BackendError::VerificationFailed)
        }
        fn get_pending_approvals(&self, _: u16) -> Result<Value, BackendError> {
            Ok(json!({"approvals":[]}))
        }
        fn resolve_receipt(&self, _: &str) -> Result<Value, BackendError> {
            Err(BackendError::NotFound)
        }
    }

    fn request(id: u64, method: &str, params: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .unwrap()
    }

    fn ready_session() -> McpSession<FixtureBackend> {
        let mut session = McpSession::new(FixtureBackend);
        let response = session.handle_line(&request(1, "initialize", json!({"protocolVersion":MCP_PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}))).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&response).unwrap()["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );
        assert!(
            session
                .handle_line(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .is_none()
        );
        session
    }

    #[test]
    fn lifecycle_blocks_early_tools_and_reused_ids() {
        let mut session = McpSession::new(FixtureBackend);
        let early: Value = serde_json::from_slice(
            &session.handle_line(&request(1, "tools/list", json!({}))).unwrap(),
        )
        .unwrap();
        assert_eq!(early["error"]["code"], -32002);
        let reused: Value =
            serde_json::from_slice(&session.handle_line(&request(1, "ping", json!({}))).unwrap())
                .unwrap();
        assert_eq!(reused["error"]["code"], -32600);
    }

    #[test]
    fn tools_are_deterministic_read_only_and_structured() {
        let mut session = ready_session();
        let listed: Value = serde_json::from_slice(
            &session.handle_line(&request(2, "tools/list", json!({}))).unwrap(),
        )
        .unwrap();
        let tools = listed["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), TOOLS.len());
        assert!(tools.iter().all(|tool| {
            tool["annotations"]["readOnlyHint"]
                == !matches!(
                    tool["name"].as_str(),
                    Some("activechain_propose_transfer" | "activechain_submit_anchor_proposal")
                )
        }));

        let called: Value = serde_json::from_slice(
            &session
                .handle_line(&request(
                    3,
                    "tools/call",
                    json!({"name":"activechain_get_status","arguments":{}}),
                ))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(called["result"]["structuredContent"]["verified"], true);
        assert_eq!(called["result"]["isError"], false);
    }

    #[test]
    fn tool_errors_are_results_but_protocol_faults_are_json_rpc_errors() {
        let mut session = ready_session();
        let execution: Value = serde_json::from_slice(
            &session
                .handle_line(&request(
                    2,
                    "tools/call",
                    json!({"name":"activechain_resolve_receipt","arguments":{"key":"00"}}),
                ))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(execution["result"]["isError"], true);
        assert_eq!(execution["result"]["structuredContent"]["error"], "not_found");
        let unknown: Value = serde_json::from_slice(
            &session
                .handle_line(&request(
                    3,
                    "tools/call",
                    json!({"name":"activechain_sign","arguments":{}}),
                ))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(unknown["error"]["code"], -32602);
    }

    #[test]
    fn oversized_malformed_and_embedded_newline_frames_fail_closed() {
        let mut session = McpSession::new(FixtureBackend);
        // Decimal 123 is an isolated opening brace. Spelling it numerically also
        // keeps the repository's intentionally simple Rust block scanner from
        // interpreting a byte literal inside this test as source structure.
        for frame in [vec![b'x'; MAX_MCP_LINE_BYTES + 1], vec![123], b"{}\n{}".to_vec()] {
            let response: Value =
                serde_json::from_slice(&session.handle_line(&frame).unwrap()).unwrap();
            assert_eq!(response["error"]["code"], -32700);
        }
    }

    #[test]
    fn runtime_rejects_arguments_excluded_by_tool_schema() {
        let mut session = ready_session();
        let response: Value = serde_json::from_slice(
            &session
                .handle_line(&request(
                    2,
                    "tools/call",
                    json!({"name":"activechain_get_status","arguments":{"surprise":true}}),
                ))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response["error"]["code"], -32602);
    }

    #[test]
    fn frozen_profile_matches_implementation_constants() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../testing/vectors/mcp-read-only-v1.json"))
                .unwrap();
        assert_eq!(fixture["protocol_version"], MCP_PROTOCOL_VERSION);
        assert_eq!(fixture["limits"]["maximum_frame_bytes"], MAX_MCP_LINE_BYTES);
        assert_eq!(fixture["limits"]["maximum_requests_per_session"], MAX_REQUESTS_PER_SESSION);
        let read_only = TOOLS
            .into_iter()
            .filter(|name| {
                !matches!(
                    *name,
                    "activechain_propose_transfer" | "activechain_submit_anchor_proposal"
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(fixture["tools"], serde_json::to_value(read_only).unwrap());
    }
}
