use activechain_application_primitives::{
    AnchorRecord, AnchorStatus, ProvidehrDemoCheckpointV1,
};
use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_protocol_types::Digest384;
use activechain_rpc_server::query;
use activechain_rpc_types::{RpcRequest, RpcResponse};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroize;

const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_SCHEMA: &str = "actum.providehr-checkpoint.http-request.v1";
const COLLECTION_PATH: &[u8] = b"/v1/demo/providehr-checkpoints";
const ITEM_PREFIX: &[u8] = b"/v1/demo/providehr-checkpoints/";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointRequest {
    schema: String,
    request_id: String,
    sequence: u64,
    clinical_decision_commitment: String,
    kline_record_commitment: String,
    dcn_event_head_commitment: String,
    previous_checkpoint: Option<String>,
    synthetic: bool,
    contains_raw_health_data: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let bind = arguments.next().unwrap_or_else(|| "0.0.0.0:8797".to_owned());
    let rpc = arguments.next().ok_or(
        "usage: activechain-providehr-demo-gateway [bind-address] <rpc-address>",
    )?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }

    let token_path = env::var("ACTUM_DEMO_BEARER_TOKEN_FILE")
        .map_err(|_| "ACTUM_DEMO_BEARER_TOKEN_FILE is required")?;
    let mut token = load_token(Path::new(&token_path))?;
    let journal_path = env::var("ACTUM_DEMO_IDEMPOTENCY_JOURNAL")
        .map_err(|_| "ACTUM_DEMO_IDEMPOTENCY_JOURNAL is required")?;
    let mut journal = IdempotencyJournal::load(PathBuf::from(journal_path))
        .map_err(|_| "could not load demo idempotency journal")?;
    let listener = TcpListener::bind(&bind)?;
    eprintln!(
        "ActiveChain ProvidEHR demo gateway listening on {}",
        listener.local_addr()?
    );

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                if let Err(error) = serve(&mut stream, &rpc, &token, &mut journal) {
                    let _ = write_error(&mut stream, 500, "internal");
                    eprintln!("ProvidEHR demo gateway request failed: {error}");
                }
            }
            Err(error) => eprintln!("ProvidEHR demo gateway connection failed: {error}"),
        }
    }
    token.zeroize();
    Ok(())
}

fn serve(
    stream: &mut TcpStream,
    rpc: &str,
    token: &[u8],
    journal: &mut IdempotencyJournal,
) -> Result<(), &'static str> {
    let request = match read_request(stream) {
        Ok(request) => request,
        Err(_) => return write_error(stream, 400, "invalid_request"),
    };

    let Some(supplied) = request.authorization.strip_prefix(b"Bearer ") else {
        return write_error(stream, 401, "unauthorized");
    };
    if !constant_time_eq(supplied, token) {
        return write_error(stream, 401, "unauthorized");
    }

    if request.method == b"GET" && request.path == b"/v1/health" {
        if !request.body.is_empty() {
            return write_error(stream, 400, "invalid_request");
        }
        return match query(rpc, &RpcRequest::Status) {
            Ok(RpcResponse::Status(status)) => write_json(
                stream,
                200,
                &json!({
                    "status": "healthy",
                    "chain_id": encode_hex(status.chain_id().digest().as_bytes()),
                    "finalized_height": status.finalized_height()
                })
                .to_string(),
            ),
            _ => write_error(stream, 503, "backend_unavailable"),
        };
    }

    if request.method == b"GET" && request.path.starts_with(ITEM_PREFIX) {
        if !request.body.is_empty() {
            return write_error(stream, 400, "invalid_request");
        }
        let reference = match parse_digest_384(&request.path[ITEM_PREFIX.len()..]) {
            Ok(reference) => reference,
            Err(_) => return write_error(stream, 400, "invalid_reference"),
        };
        return resolve_and_write(stream, rpc, reference, None);
    }

    if request.method != b"POST" || request.path != COLLECTION_PATH {
        return write_error(stream, 404, "not_found");
    }
    if request.content_type != b"application/json" {
        return write_error(stream, 415, "unsupported_media_type");
    }
    let payload: CheckpointRequest = match serde_json::from_slice(&request.body) {
        Ok(payload) => payload,
        Err(_) => return write_error(stream, 400, "invalid_request"),
    };
    if payload.schema != REQUEST_SCHEMA
        || payload.request_id.as_bytes() != request.request_id
        || payload.request_id.is_empty()
        || payload.request_id.len() > 128
    {
        return write_error(stream, 409, "idempotency_conflict");
    }

    let checkpoint = match checkpoint_from_request(&payload) {
        Ok(checkpoint) => checkpoint,
        Err(_) => return write_error(stream, 400, "invalid_checkpoint"),
    };
    let commitment = encode_hex(&checkpoint.checkpoint_commitment());
    match journal.reserve(&payload.request_id, &commitment) {
        Ok(()) => {}
        Err(JournalError::Conflict) => {
            return write_error(stream, 409, "idempotency_conflict");
        }
        Err(_) => return write_error(stream, 503, "journal_unavailable"),
    }
    let statement = checkpoint.anchor_statement().map_err(|_| "invalid checkpoint")?;
    let encoded = encode_envelope(&statement).map_err(|_| "encoding")?;
    let reference = match query(rpc, &RpcRequest::SubmitAnchor { statement: encoded }) {
        Ok(RpcResponse::AnchorSubmission(reference)) => reference,
        Ok(RpcResponse::Error(_)) => return write_error(stream, 400, "submission_rejected"),
        _ => return write_error(stream, 503, "backend_unavailable"),
    };
    resolve_and_write(stream, rpc, reference, Some(&statement))
}

fn checkpoint_from_request(
    payload: &CheckpointRequest,
) -> Result<ProvidehrDemoCheckpointV1, &'static str> {
    let previous = payload
        .previous_checkpoint
        .as_deref()
        .map(|value| parse_digest_384(value.as_bytes()))
        .transpose()?;
    ProvidehrDemoCheckpointV1::new(
        payload.sequence,
        parse_digest_256(&payload.clinical_decision_commitment)?,
        parse_digest_256(&payload.kline_record_commitment)?,
        parse_digest_256(&payload.dcn_event_head_commitment)?,
        previous,
        payload.synthetic,
        payload.contains_raw_health_data,
    )
    .map_err(|_| "invalid checkpoint")
}

fn resolve_and_write(
    stream: &mut TcpStream,
    rpc: &str,
    reference: Digest384,
    expected: Option<&activechain_application_primitives::DigestAnchorStatementV1>,
) -> Result<(), &'static str> {
    let attempts = if expected.is_some() { 20 } else { 1 };
    let mut lifecycle = "submitted";
    for attempt in 0..attempts {
        match query(rpc, &RpcRequest::ResolveAnchor { reference }) {
            Ok(RpcResponse::AnchorRecord(bytes)) => {
                let record = decode_envelope::<AnchorRecord>(&bytes)
                    .map_err(|_| "malformed backend response")?;
                if expected.is_some_and(|statement| record.statement() != statement) {
                    return write_error(stream, 502, "malformed_backend_response");
                }
                lifecycle = match record.status() {
                    AnchorStatus::Pending if record.submitted_transaction().is_some() => "submitted",
                    AnchorStatus::Pending => "pending",
                    AnchorStatus::Finalized => "finalized",
                    AnchorStatus::Rejected => "rejected",
                };
                if matches!(record.status(), AnchorStatus::Finalized | AnchorStatus::Rejected) {
                    break;
                }
            }
            Ok(RpcResponse::Error(_)) => lifecycle = "submitted",
            _ => return write_error(stream, 503, "backend_unavailable"),
        }
        if attempt + 1 < attempts {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let http_status = if lifecycle == "pending" || lifecycle == "submitted" {
        202
    } else {
        200
    };
    write_json(
        stream,
        http_status,
        &json!({
            "schema": "actum.providehr-checkpoint.lifecycle.v1",
            "status": lifecycle,
            "reference": encode_hex(reference.as_bytes())
        })
        .to_string(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalError {
    Conflict,
    Invalid,
    Io,
}

struct IdempotencyJournal {
    path: PathBuf,
    entries: BTreeMap<String, String>,
}

impl IdempotencyJournal {
    fn load(path: PathBuf) -> Result<Self, JournalError> {
        let entries = if path.exists() {
            let metadata = fs::symlink_metadata(&path).map_err(|_| JournalError::Io)?;
            if !metadata.file_type().is_file() {
                return Err(JournalError::Invalid);
            }
            serde_json::from_slice(&fs::read(&path).map_err(|_| JournalError::Io)?)
                .map_err(|_| JournalError::Invalid)?
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, entries })
    }

    fn reserve(&mut self, request_id: &str, commitment: &str) -> Result<(), JournalError> {
        match self.entries.get(request_id) {
            Some(existing) if existing == commitment => return Ok(()),
            Some(_) => return Err(JournalError::Conflict),
            None => {}
        }
        let mut next = self.entries.clone();
        next.insert(request_id.to_owned(), commitment.to_owned());
        let bytes = serde_json::to_vec(&next).map_err(|_| JournalError::Invalid)?;
        let temporary = self.path.with_extension("tmp");
        let mut file = fs::File::create(&temporary).map_err(|_| JournalError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| JournalError::Io)?;
        }
        file.write_all(&bytes).map_err(|_| JournalError::Io)?;
        file.sync_all().map_err(|_| JournalError::Io)?;
        fs::rename(&temporary, &self.path).map_err(|_| JournalError::Io)?;
        self.entries = next;
        Ok(())
    }
}

struct HttpRequest {
    method: Vec<u8>,
    path: Vec<u8>,
    authorization: Vec<u8>,
    request_id: Vec<u8>,
    content_type: Vec<u8>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, &'static str> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let count = stream.read(&mut chunk).map_err(|_| "read")?;
        if count == 0 {
            return Err("truncated request");
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > MAX_HEADERS + MAX_BODY {
            return Err("request too large");
        }
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            if index + 4 > MAX_HEADERS {
                return Err("headers too large");
            }
            break index + 4;
        }
    };

    let headers = &bytes[..header_end - 4];
    let mut lines = headers.split(|byte| *byte == b'\n').map(trim_cr);
    let mut request_line = lines
        .next()
        .ok_or("missing request line")?
        .split(|byte| *byte == b' ');
    let method = request_line.next().ok_or("missing method")?.to_vec();
    let path = request_line.next().ok_or("missing path")?.to_vec();
    if request_line.next() != Some(b"HTTP/1.1".as_slice()) || request_line.next().is_some() {
        return Err("invalid request line");
    }

    let mut authorization = None;
    let mut request_id = Vec::new();
    let mut content_type = Vec::new();
    let mut content_length = None;
    for line in lines {
        let separator = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or("invalid header")?;
        let name = &line[..separator];
        let value = trim_ascii(&line[separator + 1..]);
        if name.eq_ignore_ascii_case(b"authorization") {
            if authorization.replace(value.to_vec()).is_some() {
                return Err("duplicate authorization");
            }
        } else if name.eq_ignore_ascii_case(b"x-actum-request-id") {
            if !request_id.is_empty() {
                return Err("duplicate request id");
            }
            request_id = value.to_vec();
        } else if name.eq_ignore_ascii_case(b"content-type") {
            if !content_type.is_empty() {
                return Err("duplicate content type");
            }
            content_type = value.to_vec();
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err("duplicate content length");
            }
            let text = std::str::from_utf8(value).map_err(|_| "invalid content length")?;
            content_length = Some(text.parse::<usize>().map_err(|_| "invalid content length")?);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err("transfer encoding unsupported");
        }
    }

    let length = content_length.unwrap_or(0);
    if length > MAX_BODY || bytes.len() - header_end > length {
        return Err("invalid body length");
    }
    while bytes.len() - header_end < length {
        let remaining = length - (bytes.len() - header_end);
        let capacity = chunk.len();
        let count = stream
            .read(&mut chunk[..remaining.min(capacity)])
            .map_err(|_| "read")?;
        if count == 0 {
            return Err("truncated body");
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(HttpRequest {
        method,
        path,
        authorization: authorization.unwrap_or_default(),
        request_id,
        content_type,
        body: bytes[header_end..].to_vec(),
    })
}

fn parse_digest_256(value: &str) -> Result<[u8; 32], &'static str> {
    let bytes = decode_hex(value.as_bytes(), 32)?;
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

fn parse_digest_384(value: &[u8]) -> Result<Digest384, &'static str> {
    let bytes = decode_hex(value, 48)?;
    let mut digest = [0_u8; 48];
    digest.copy_from_slice(&bytes);
    Ok(Digest384::new(digest))
}

fn decode_hex(value: &[u8], byte_length: usize) -> Result<Vec<u8>, &'static str> {
    if value.len() != byte_length * 2 {
        return Err("invalid digest");
    }
    value
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or("invalid digest")?;
            let low = hex_nibble(pair[1]).ok_or("invalid digest")?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

fn load_token(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err("demo bearer token must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("demo bearer token must not be group/world accessible".into());
        }
    }
    let mut token = fs::read(path)?;
    while token.last().is_some_and(u8::is_ascii_whitespace) {
        token.pop();
    }
    if !(32..=256).contains(&token.len()) || token.iter().any(|byte| !byte.is_ascii_graphic()) {
        token.zeroize();
        return Err("demo bearer token must contain 32-256 non-whitespace bytes".into());
    }
    Ok(token)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn write_error(stream: &mut TcpStream, status: u16, code: &str) -> Result<(), &'static str> {
    write_json(
        stream,
        status,
        &json!({"status": "error", "code": code}).to_string(),
    )
}

fn write_json(stream: &mut TcpStream, status: u16, body: &str) -> Result<(), &'static str> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(|_| "write")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> CheckpointRequest {
        CheckpointRequest {
            schema: REQUEST_SCHEMA.to_owned(),
            request_id: "episode-1".to_owned(),
            sequence: 1,
            clinical_decision_commitment: "11".repeat(32),
            kline_record_commitment: "22".repeat(32),
            dcn_event_head_commitment: "33".repeat(32),
            previous_checkpoint: None,
            synthetic: true,
            contains_raw_health_data: false,
        }
    }

    #[test]
    fn checkpoint_request_projects_into_native_statement() {
        let checkpoint = checkpoint_from_request(&payload()).unwrap();
        assert_eq!(checkpoint.sequence(), 1);
        assert!(checkpoint.anchor_statement().is_ok());
    }

    #[test]
    fn raw_health_data_is_rejected_before_rpc_submission() {
        let mut value = payload();
        value.contains_raw_health_data = true;
        assert!(checkpoint_from_request(&value).is_err());
    }

    #[test]
    fn digest_parser_is_strict_lowercase_hex() {
        assert_eq!(parse_digest_256(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(parse_digest_256(&"AB".repeat(32)).is_err());
        assert!(parse_digest_256("ab").is_err());
    }
}
