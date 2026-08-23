use activechain_protocol_types::Digest384;
use activechain_work_proof_verifier::api::{
    ApiRequestErrorV1, MAX_STATEFUL_VERIFY_REQUEST_BYTES, StatefulVerificationErrorResponseV1,
    StatefulVerificationResponseV1, decode_digest_hex, decode_stateful_verification_request,
    rate_limit_client_id,
};
use activechain_work_proof_verifier::{
    DurableTrustStore, DurableUsageRegistry, FixedWindowRateLimiter, SubprocessRelationVerifier,
    VerificationErrorCodeV1, VerificationErrorV1, WorkProofVerificationService,
};
use serde::Serialize;
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

const MAX_HEADERS: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIA_TYPE: &[u8] = b"application/vnd.actum.work-proof.v1+json";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let bind = arguments.next().ok_or(
        "usage: actum-work-proof-api <bind> <trust-store> <usage-store> <relation-verifier> <bearer-token-file>",
    )?;
    let trust = DurableTrustStore::open(arguments.next().ok_or("trust store is required")?)?;
    let usage = DurableUsageRegistry::open(arguments.next().ok_or("usage store is required")?)?;
    let verifier = arguments.next().ok_or("relation verifier is required")?;
    let token_path = arguments.next().ok_or("bearer token file is required")?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let relation = SubprocessRelationVerifier::new(verifier, VERIFY_TIMEOUT);
    let service = WorkProofVerificationService::new(
        relation,
        trust,
        usage,
        FixedWindowRateLimiter::new(60, 60_000)?,
    );
    let mut token = load_token(Path::new(&token_path))?;
    let listener = TcpListener::bind(bind)?;
    eprintln!("Actum work-proof API listening on {}", listener.local_addr()?);
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let source = stream
                    .peer_addr()
                    .map(|address| address.ip().to_string())
                    .unwrap_or_else(|_| "unknown".to_owned());
                if serve(&mut stream, &service, &token, rate_limit_client_id(source.as_bytes()))
                    .is_err()
                {
                    let _ = write_error(&mut stream, 500, "internal");
                }
            }
            Err(error) => eprintln!("work-proof API connection failed: {error}"),
        }
    }
    token.zeroize();
    Ok(())
}

fn serve<R: activechain_work_proof_verifier::RelationVerifier>(
    stream: &mut TcpStream,
    service: &WorkProofVerificationService<R>,
    token: &[u8],
    client_id: Digest384,
) -> Result<(), &'static str> {
    let request = match read_request(stream) {
        Ok(request) => request,
        Err(_) => return write_error(stream, 400, "malformed_request"),
    };
    let Some(supplied) = request.authorization.strip_prefix(b"Bearer ") else {
        return write_error(stream, 401, "unauthorized");
    };
    if !constant_time_eq(supplied, token) {
        return write_error(stream, 401, "unauthorized");
    }
    if request.method == b"GET" && request.path == b"/v1/status" {
        if !request.body.is_empty() {
            return write_error(stream, 400, "malformed_request");
        }
        return match service.status(now_ms()?) {
            Ok(status) => write_json(stream, 200, &status),
            Err(error) => {
                write_json(stream, 503, &StatusErrorResponseV1 { status: "error", error })
            }
        };
    }
    if request.method == b"GET" && request.path.starts_with(b"/v1/claims/") {
        if !request.body.is_empty() {
            return write_error(stream, 400, "malformed_request");
        }
        let value = std::str::from_utf8(&request.path[b"/v1/claims/".len()..])
            .ok()
            .and_then(decode_digest_hex);
        let Some(claim_id) = value else {
            return write_error(stream, 400, "malformed_request");
        };
        return match service.claim(claim_id) {
            Ok(Some(claim)) => write_json(stream, 200, &claim),
            Ok(None) => write_error(stream, 404, "not_found"),
            Err(_) => write_error(stream, 503, "persistence_unavailable"),
        };
    }
    if request.method == b"GET" && request.path.starts_with(b"/v1/claims?") {
        if !request.body.is_empty() {
            return write_error(stream, 400, "malformed_request");
        }
        let Some((cursor, limit)) = parse_claim_query(&request.path) else {
            return write_error(stream, 400, "malformed_request");
        };
        return match service.list_claims(cursor, limit) {
            Ok(page) => write_json(stream, 200, &page),
            Err(_) => write_error(stream, 503, "persistence_unavailable"),
        };
    }
    if request.method != b"POST" || request.path != b"/v1/proofs/verify" {
        return write_error(stream, 404, "not_found");
    }
    if request.content_type != MEDIA_TYPE {
        return write_error(stream, 415, "unsupported_media_type");
    }
    let verification = match decode_stateful_verification_request(&request.body, client_id) {
        Ok(request) => request,
        Err(ApiRequestErrorV1::Malformed) => return write_error(stream, 400, "malformed_request"),
        Err(ApiRequestErrorV1::Unsupported) => return write_error(stream, 400, "unsupported"),
    };
    match service.verify(&verification, now_ms()?) {
        Ok(result) => write_json(stream, 200, &StatefulVerificationResponseV1::new(result)),
        Err(error) => {
            let status = match error.code {
                VerificationErrorCodeV1::RateLimited => 429,
                VerificationErrorCodeV1::UsageDoubleSpend => 409,
                VerificationErrorCodeV1::VerifierUnavailable
                | VerificationErrorCodeV1::VerifierTimeout
                | VerificationErrorCodeV1::PersistenceUnavailable => 503,
                _ => 400,
            };
            write_json(stream, status, &StatefulVerificationErrorResponseV1::new(error))
        }
    }
}

#[derive(Serialize)]
struct StatusErrorResponseV1 {
    status: &'static str,
    error: VerificationErrorV1,
}

struct HttpRequest {
    method: Vec<u8>,
    path: Vec<u8>,
    authorization: Vec<u8>,
    content_type: Vec<u8>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, ()> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut chunk).map_err(|_| ())?;
        if count == 0 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
        if bytes.len() > MAX_HEADERS {
            return Err(());
        }
    };
    if header_end > MAX_HEADERS {
        return Err(());
    }
    let header = &bytes[..header_end - 4];
    let mut lines = header.split(|byte| *byte == b'\n').map(trim_cr);
    let mut request_line = lines.next().ok_or(())?.split(|byte| *byte == b' ');
    let method = request_line.next().ok_or(())?.to_vec();
    let path = request_line.next().ok_or(())?.to_vec();
    if request_line.next() != Some(b"HTTP/1.1".as_slice()) || request_line.next().is_some() {
        return Err(());
    }
    let mut authorization = None;
    let mut content_type = None;
    let mut content_length = None;
    for line in lines {
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            return Err(());
        };
        let name = &line[..separator];
        let value = trim_ascii(&line[separator + 1..]);
        if name.eq_ignore_ascii_case(b"authorization") {
            if authorization.replace(value.to_vec()).is_some() {
                return Err(());
            }
        } else if name.eq_ignore_ascii_case(b"content-type") {
            if content_type.replace(value.to_vec()).is_some() {
                return Err(());
            }
        } else if name.eq_ignore_ascii_case(b"content-length") {
            let value =
                std::str::from_utf8(value).map_err(|_| ())?.parse::<usize>().map_err(|_| ())?;
            if value > MAX_STATEFUL_VERIFY_REQUEST_BYTES || content_length.replace(value).is_some()
            {
                return Err(());
            }
        }
    }
    let length = content_length.unwrap_or(0);
    if bytes.len() - header_end > length {
        return Err(());
    }
    while bytes.len() - header_end < length {
        let remaining = length - (bytes.len() - header_end);
        let maximum = remaining.min(chunk.len());
        let count = stream.read(&mut chunk[..maximum]).map_err(|_| ())?;
        if count == 0 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(HttpRequest {
        method,
        path,
        authorization: authorization.unwrap_or_default(),
        content_type: content_type.unwrap_or_default(),
        body: bytes[header_end..].to_vec(),
    })
}

fn parse_claim_query(path: &[u8]) -> Option<(Option<Digest384>, usize)> {
    let query = std::str::from_utf8(path.strip_prefix(b"/v1/claims?")?).ok()?;
    let mut cursor = None;
    let mut limit = None;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=')?;
        match name {
            "cursor" if cursor.is_none() => cursor = Some(decode_digest_hex(value)?),
            "limit" if limit.is_none() => limit = Some(value.parse::<usize>().ok()?),
            _ => return None,
        }
    }
    let limit = limit.unwrap_or(20);
    (1..=activechain_work_proof_verifier::MAX_PAGE_SIZE).contains(&limit).then_some((cursor, limit))
}

fn now_ms() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock")?
        .as_millis()
        .try_into()
        .map_err(|_| "clock")
}

fn load_token(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err("bearer token must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("bearer token must be private".into());
        }
    }
    let mut token = fs::read(path)?;
    while token.last().is_some_and(u8::is_ascii_whitespace) {
        token.pop();
    }
    if !(32..=256).contains(&token.len()) || token.iter().any(|byte| !byte.is_ascii_graphic()) {
        token.zeroize();
        return Err("bearer token must contain 32-256 graphic ASCII bytes".into());
    }
    Ok(token)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).fold(0_u8, |difference, (a, b)| difference | (a ^ b)) == 0
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
    write_json(stream, status, &serde_json::json!({"status":"error","code":code}))
}

fn write_json(
    stream: &mut TcpStream,
    status: u16,
    value: &impl Serialize,
) -> Result<(), &'static str> {
    let body = serde_json::to_vec(value).map_err(|_| "encode")?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .map_err(|_| "write")?;
    stream.write_all(&body).map_err(|_| "write")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_comparison_and_claim_queries_are_exact() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"diff"));
        assert!(!constant_time_eq(b"short", b"longer"));
        assert_eq!(parse_claim_query(b"/v1/claims?limit=10"), Some((None, 10)));
        assert!(parse_claim_query(b"/v1/claims?limit=0").is_none());
        assert!(parse_claim_query(b"/v1/claims?limit=101").is_none());
        assert!(parse_claim_query(b"/v1/claims?limit=0&limit=1").is_none());
        assert!(parse_claim_query(b"/v1/claims?unknown=1").is_none());
    }

    #[test]
    fn status_errors_preserve_the_safe_typed_reason() {
        let body = serde_json::to_value(StatusErrorResponseV1 {
            status: "error",
            error: VerificationErrorV1 {
                code: VerificationErrorCodeV1::StaleTrust,
                retryable: false,
            },
        })
        .unwrap();
        assert_eq!(body["status"], "error");
        assert_eq!(body["error"]["code"], "stale_trust");
        assert_eq!(body["error"]["retryable"], false);
    }
}
