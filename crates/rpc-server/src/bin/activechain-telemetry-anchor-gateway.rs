use activechain_application_primitives::{
    AnchorRecord, AnchorStatus, TelemetryEpochAnchorRequestV1,
};
use activechain_canonical_codec::{decode_envelope, encode_envelope};
use activechain_protocol_types::Digest384;
use activechain_rpc_server::query;
use activechain_rpc_types::{Health, RpcRequest, RpcResponse};
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
const MAX_BODY: usize = 256 * 1024;
const MAX_IDEMPOTENCY_RECORDS: usize = 65_536;
const JOURNAL_MAGIC: &[u8] = b"ACTUM-ANCHOR-IDEMPOTENCY-V1\n";
const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let bind = arguments.next().unwrap_or_else(|| "127.0.0.1:49154".to_owned());
    let rpc = arguments
        .next()
        .ok_or("usage: activechain-telemetry-anchor-gateway [bind-address] <rpc-address>")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let token_path = env::var("ACTUM_ANCHOR_BEARER_TOKEN_FILE")
        .map_err(|_| "ACTUM_ANCHOR_BEARER_TOKEN_FILE is required")?;
    let mut token = load_token(Path::new(&token_path))?;
    let journal_path = env::var("ACTUM_ANCHOR_IDEMPOTENCY_JOURNAL")
        .map_err(|_| "ACTUM_ANCHOR_IDEMPOTENCY_JOURNAL is required")?;
    let mut journal = IdempotencyJournal::load(PathBuf::from(journal_path))
        .map_err(|_| "could not load anchor idempotency journal")?;
    let listener = TcpListener::bind(&bind)?;
    eprintln!("ActiveChain telemetry anchor gateway listening on {}", listener.local_addr()?);
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                if let Err(error) = serve(&mut stream, &rpc, &token, &mut journal) {
                    let _ = write_error(&mut stream, 500, "internal");
                    eprintln!("anchor gateway request failed: {error}");
                }
            }
            Err(error) => eprintln!("anchor gateway connection failed: {error}"),
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
    let request = read_request(stream)?;
    let Some(supplied) = request.authorization.strip_prefix(b"Bearer ") else {
        return write_error(stream, 401, "unauthorized");
    };
    if !constant_time_eq(supplied, token) {
        return write_error(stream, 401, "unauthorized");
    }
    let status = match query(rpc, &RpcRequest::Status) {
        Ok(RpcResponse::Status(status)) => status,
        _ => return write_error(stream, 503, "backend_unavailable"),
    };
    if request.method == b"GET" && request.path == b"/v1/health" {
        if !request.body.is_empty() || status.health() != Health::Healthy {
            return write_error(stream, 503, "backend_unavailable");
        }
        return write_json(
            stream,
            200,
            &format!(
                "{{\"status\":\"healthy\",\"chain_id\":\"{}\",\"genesis_commitment\":\"{}\",\"finalized_height\":{}}}",
                hex(*status.chain_id().digest()),
                hex(status.genesis_commitment()),
                status.finalized_height()
            ),
        );
    }
    if request.method != b"POST" || request.path != b"/v1/anchors" {
        return write_error(stream, 404, "not_found");
    }
    if request.content_type != b"application/octet-stream" {
        return write_error(stream, 415, "unsupported_media_type");
    }
    let anchor: TelemetryEpochAnchorRequestV1 = match decode_envelope(&request.body) {
        Ok(anchor) => anchor,
        Err(_) => return write_error(stream, 400, "invalid_request"),
    };
    if request.request_id != anchor.client_request_id {
        return write_error(stream, 409, "idempotency_conflict");
    }
    if anchor.chain_id != *status.chain_id().digest()
        || anchor.genesis_commitment != status.genesis_commitment()
    {
        return write_error(stream, 409, "wrong_network");
    }
    let request_commitment = anchor.request_commitment().map_err(|_| "encoding")?;
    match journal.reserve(&anchor.client_request_id, request_commitment) {
        Ok(()) => {}
        Err(JournalError::Conflict) => {
            return write_error(stream, 409, "idempotency_conflict");
        }
        Err(_) => return write_error(stream, 503, "journal_unavailable"),
    }
    let statement = anchor.statement().map_err(|_| "invalid statement")?;
    let encoded = encode_envelope(&statement).map_err(|_| "encoding")?;
    let reference = match query(rpc, &RpcRequest::SubmitAnchor { statement: encoded }) {
        Ok(RpcResponse::AnchorSubmission(reference)) => reference,
        Ok(RpcResponse::Error(_)) => return write_error(stream, 400, "submission_rejected"),
        _ => return write_error(stream, 503, "backend_unavailable"),
    };
    let lifecycle = match query(rpc, &RpcRequest::ResolveAnchor { reference }) {
        Ok(RpcResponse::AnchorRecord(bytes)) => match decode_envelope::<AnchorRecord>(&bytes) {
            Ok(record) if record.statement() == &statement => match record.status() {
                AnchorStatus::Pending => "pending",
                AnchorStatus::Finalized => "finalized",
                AnchorStatus::Rejected => "rejected",
            },
            _ => return write_error(stream, 502, "malformed_backend_response"),
        },
        Ok(RpcResponse::Error(_)) => "submitted",
        _ => return write_error(stream, 503, "backend_unavailable"),
    };
    write_json(
        stream,
        200,
        &format!(
            "{{\"status\":\"{lifecycle}\",\"chain_id\":\"{}\",\"genesis_commitment\":\"{}\",\"reference\":\"{}\"}}",
            hex(*status.chain_id().digest()),
            hex(status.genesis_commitment()),
            hex(reference)
        ),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalError {
    Invalid,
    Capacity,
    Conflict,
    Io,
}

#[derive(Default)]
struct IdempotencyJournal {
    path: Option<PathBuf>,
    entries: BTreeMap<Vec<u8>, Digest384>,
}

impl IdempotencyJournal {
    fn load(path: PathBuf) -> Result<Self, JournalError> {
        if !path.exists() {
            return Ok(Self { path: Some(path), entries: BTreeMap::new() });
        }
        let metadata = fs::symlink_metadata(&path).map_err(|_| JournalError::Io)?;
        if !metadata.file_type().is_file() {
            return Err(JournalError::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(JournalError::Invalid);
            }
        }
        let bytes = fs::read(&path).map_err(|_| JournalError::Io)?;
        if !bytes.starts_with(JOURNAL_MAGIC) {
            return Err(JournalError::Invalid);
        }
        let mut cursor = JOURNAL_MAGIC.len();
        let mut entries = BTreeMap::new();
        while cursor < bytes.len() {
            let length = usize::from(*bytes.get(cursor).ok_or(JournalError::Invalid)?);
            cursor += 1;
            if length == 0 || length > 128 || cursor + length + 48 > bytes.len() {
                return Err(JournalError::Invalid);
            }
            let request_id = bytes[cursor..cursor + length].to_vec();
            cursor += length;
            let mut commitment = [0_u8; 48];
            commitment.copy_from_slice(&bytes[cursor..cursor + 48]);
            cursor += 48;
            if entries.insert(request_id, Digest384::new(commitment)).is_some()
                || entries.len() > MAX_IDEMPOTENCY_RECORDS
            {
                return Err(JournalError::Invalid);
            }
        }
        Ok(Self { path: Some(path), entries })
    }

    fn reserve(&mut self, request_id: &[u8], commitment: Digest384) -> Result<(), JournalError> {
        match self.entries.get(request_id) {
            Some(existing) if *existing == commitment => return Ok(()),
            Some(_) => return Err(JournalError::Conflict),
            None if self.entries.len() >= MAX_IDEMPOTENCY_RECORDS => {
                return Err(JournalError::Capacity);
            }
            None => {}
        }
        let mut next = self.entries.clone();
        next.insert(request_id.to_vec(), commitment);
        if let Some(path) = &self.path {
            persist_journal(path, &next)?;
        }
        self.entries = next;
        Ok(())
    }
}

fn persist_journal(
    path: &Path,
    entries: &BTreeMap<Vec<u8>, Digest384>,
) -> Result<(), JournalError> {
    let mut bytes = JOURNAL_MAGIC.to_vec();
    for (request_id, commitment) in entries {
        bytes.push(u8::try_from(request_id.len()).map_err(|_| JournalError::Invalid)?);
        bytes.extend_from_slice(request_id);
        bytes.extend_from_slice(commitment.as_bytes());
    }
    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary).map_err(|_| JournalError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|_| JournalError::Io)?;
    }
    file.write_all(&bytes).map_err(|_| JournalError::Io)?;
    file.sync_all().map_err(|_| JournalError::Io)?;
    fs::rename(&temporary, path).map_err(|_| JournalError::Io)?;
    let parent =
        path.parent().filter(|value| !value.as_os_str().is_empty()).unwrap_or(Path::new("."));
    fs::File::open(parent).and_then(|directory| directory.sync_all()).map_err(|_| JournalError::Io)
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
    let mut request_line = lines.next().ok_or("missing request line")?.split(|byte| *byte == b' ');
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
        let separator = line.iter().position(|byte| *byte == b':').ok_or("invalid header")?;
        let name = &line[..separator];
        let value = trim_ascii(&line[separator + 1..]);
        if name.eq_ignore_ascii_case(b"authorization") {
            if authorization.replace(value.to_vec()).is_some() {
                return Err("duplicate authorization");
            }
        } else if name.eq_ignore_ascii_case(b"x-actum-request-id") {
            request_id = value.to_vec();
        } else if name.eq_ignore_ascii_case(b"content-type") {
            content_type = value.to_vec();
        } else if name.eq_ignore_ascii_case(b"content-length") {
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
        let count = stream.read(&mut chunk[..remaining.min(capacity)]).map_err(|_| "read")?;
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

fn load_token(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err("anchor bearer token must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("anchor bearer token must not be group/world accessible".into());
        }
    }
    let mut token = fs::read(path)?;
    while token.last().is_some_and(u8::is_ascii_whitespace) {
        token.pop();
    }
    if !(32..=256).contains(&token.len()) || token.iter().any(u8::is_ascii_whitespace) {
        token.zeroize();
        return Err("anchor bearer token must contain 32-256 non-whitespace bytes".into());
    }
    Ok(token)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0_u8, |difference, (a, b)| difference | (a ^ b)) == 0
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

fn hex(digest: Digest384) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(96);
    for byte in digest.as_bytes() {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

fn write_error(stream: &mut TcpStream, status: u16, code: &str) -> Result<(), &'static str> {
    write_json(stream, status, &format!("{{\"status\":\"error\",\"code\":\"{code}\"}}"))
}

fn write_json(stream: &mut TcpStream, status: u16, body: &str) -> Result<(), &'static str> {
    let reason = match status {
        200 => "OK",
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
    use activechain_application_primitives::{ActivityEpochV1, AnchorRegistry};
    use activechain_protocol_types::ChainId;
    use activechain_rpc_types::{ProofKind, RpcStatus};
    use std::{net::Shutdown, thread};

    #[test]
    fn bearer_comparison_is_exact() {
        assert!(constant_time_eq(
            b"abcdefghijklmnopqrstuvwxyz012345",
            b"abcdefghijklmnopqrstuvwxyz012345"
        ));
        assert!(!constant_time_eq(
            b"abcdefghijklmnopqrstuvwxyz012345",
            b"abcdefghijklmnopqrstuvwxyz012346"
        ));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn missing_bearer_is_rejected_before_backend_access() {
        let response = exercise(
            "127.0.0.1:1",
            b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            b"abcdefghijklmnopqrstuvwxyz012345",
        );
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized"));
        assert!(response.contains("\"code\":\"unauthorized\""));
    }

    #[test]
    fn healthy_authenticated_request_fails_closed_when_backend_is_down() {
        let response = exercise(
            "127.0.0.1:1",
            b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz012345\r\n\r\n".to_vec(),
            b"abcdefghijklmnopqrstuvwxyz012345",
        );
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(response.contains("\"code\":\"backend_unavailable\""));
    }

    #[test]
    fn wrong_chain_anchor_is_rejected_before_submission() {
        let backend = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let backend_address = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length).unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).unwrap();
            let status = RpcStatus::new(
                ChainId::new(digest(1)),
                digest(2),
                1,
                10,
                100,
                100,
                30,
                vec![ProofKind::FinalityCertificate],
            )
            .unwrap();
            let response = encode_envelope(&RpcResponse::Status(status)).unwrap();
            stream.write_all(&(response.len() as u32).to_be_bytes()).unwrap();
            stream.write_all(&response).unwrap();
        });
        let request = TelemetryEpochAnchorRequestV1::new(
            digest(9),
            digest(2),
            1,
            digest(3),
            b"wrong-chain".to_vec(),
            epoch(),
        )
        .unwrap();
        let body = encode_envelope(&request).unwrap();
        let mut http = format!(
            "POST /v1/anchors HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz012345\r\nContent-Type: application/octet-stream\r\nX-Actum-Request-Id: wrong-chain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        http.extend_from_slice(&body);
        let response =
            exercise(&backend_address.to_string(), http, b"abcdefghijklmnopqrstuvwxyz012345");
        backend_thread.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 409 Conflict"));
        assert!(response.contains("\"code\":\"wrong_network\""));
    }

    #[test]
    fn canonical_anchor_submission_resolves_exact_pending_record() {
        let request = TelemetryEpochAnchorRequestV1::new(
            digest(1),
            digest(2),
            1,
            digest(3),
            b"anchor-happy".to_vec(),
            epoch(),
        )
        .unwrap();
        let statement = request.statement().unwrap();
        let mut registry = AnchorRegistry::default();
        let reference = registry.submit(statement).unwrap();
        let record = registry.resolve(reference).unwrap().clone();
        let backend = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let backend_address = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let responses = [
                RpcResponse::Status(
                    RpcStatus::new(
                        ChainId::new(digest(1)),
                        digest(2),
                        1,
                        10,
                        100,
                        100,
                        30,
                        vec![ProofKind::FinalityCertificate],
                    )
                    .unwrap(),
                ),
                RpcResponse::AnchorSubmission(reference),
                RpcResponse::AnchorRecord(encode_envelope(&record).unwrap()),
            ];
            for response in responses {
                let (mut stream, _) = backend.accept().unwrap();
                let mut length = [0_u8; 4];
                stream.read_exact(&mut length).unwrap();
                let mut body = vec![0_u8; u32::from_be_bytes(length) as usize];
                stream.read_exact(&mut body).unwrap();
                let response = encode_envelope(&response).unwrap();
                stream.write_all(&(response.len() as u32).to_be_bytes()).unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        let body = encode_envelope(&request).unwrap();
        let mut http = format!(
            "POST /v1/anchors HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz012345\r\nContent-Type: application/octet-stream\r\nX-Actum-Request-Id: anchor-happy\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        http.extend_from_slice(&body);
        let response =
            exercise(&backend_address.to_string(), http, b"abcdefghijklmnopqrstuvwxyz012345");
        backend_thread.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"status\":\"pending\""));
        assert!(response.contains(&format!("\"reference\":\"{}\"", hex(reference))));
    }

    #[test]
    fn oversized_declared_body_is_rejected_without_allocation() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream)
        });
        let mut client = TcpStream::connect(address).unwrap();
        write!(client, "POST /v1/anchors HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1)
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert!(server.join().unwrap().is_err());
    }

    fn exercise(rpc: &str, request: Vec<u8>, token: &[u8]) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let rpc = rpc.to_owned();
        let token = token.to_vec();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut journal = IdempotencyJournal::default();
            serve(&mut stream, &rpc, &token, &mut journal)
        });
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(&request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server.join().unwrap().unwrap();
        response
    }

    fn digest(byte: u8) -> Digest384 {
        Digest384::new([byte; 48])
    }

    fn epoch() -> ActivityEpochV1 {
        ActivityEpochV1 {
            collector_id: digest(4),
            project_id: digest(5),
            first_collector_sequence: 1,
            last_collector_sequence: 1,
            first_project_sequence: 1,
            last_project_sequence: 1,
            event_count: 1,
            wall_start_ms: 100,
            wall_end_ms: 200,
            monotonic_start_ns: 1_000,
            monotonic_end_ns: 2_000,
            event_root: digest(6),
            previous_epoch_id: Digest384::ZERO,
            authorization_revision: 1,
            policy_id: digest(7),
        }
    }

    #[test]
    fn idempotency_journal_survives_restart_and_rejects_conflicts() {
        let path = std::env::temp_dir()
            .join(format!("activechain-anchor-idempotency-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let mut journal = IdempotencyJournal::load(path.clone()).unwrap();
        journal.reserve(b"request-1", digest(1)).unwrap();
        journal.reserve(b"request-1", digest(1)).unwrap();
        assert_eq!(journal.reserve(b"request-1", digest(2)), Err(JournalError::Conflict));
        let mut restored = IdempotencyJournal::load(path.clone()).unwrap();
        assert_eq!(restored.reserve(b"request-1", digest(2)), Err(JournalError::Conflict));
        fs::remove_file(path).unwrap();
    }
}
