use activechain_work_proof_verifier::delivery::{
    DeliveryError, DurableDeliveryStore, MAX_DELIVERY_ARTIFACT_BYTES,
};
use serde::Serialize;
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    time::Duration,
};
use zeroize::Zeroize;

const MAX_HEADERS: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let bind = arguments.next().ok_or(
        "usage: actum-work-delivery-api <bind> <store-directory> <bearer-token-file> <chain-id> <genesis-commitment> <deployment-revision>",
    )?;
    let mut store = DurableDeliveryStore::open(arguments.next().ok_or("store is required")?)
        .map_err(|_| "delivery store could not be opened")?;
    let token_path = arguments.next().ok_or("bearer token file is required")?;
    let mut token = load_token(Path::new(&token_path))?;
    let chain_id = validate_digest(arguments.next().ok_or("chain ID is required")?)?;
    let genesis_commitment =
        validate_digest(arguments.next().ok_or("genesis commitment is required")?)?;
    let deployment_revision =
        validate_revision(arguments.next().ok_or("deployment revision is required")?)?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let identity = Identity { chain_id, genesis_commitment, deployment_revision };
    let listener = TcpListener::bind(bind)?;
    eprintln!("Actum work delivery API listening on {}", listener.local_addr()?);
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                if serve(&mut stream, &identity, &token, &mut store).is_err() {
                    let _ = write_error(&mut stream, 500, "internal");
                }
            }
            Err(error) => eprintln!("work delivery connection failed: {error}"),
        }
    }
    token.zeroize();
    Ok(())
}

#[derive(Clone)]
struct Identity {
    chain_id: String,
    genesis_commitment: String,
    deployment_revision: String,
}

#[derive(Serialize)]
struct HealthResponse<'a> {
    status: &'static str,
    chain_id: &'a str,
    genesis_commitment: &'a str,
    deployment_revision: &'a str,
    durable_receipts: usize,
}

#[derive(Serialize)]
struct DeliveryResponse<'a> {
    status: &'static str,
    chain_id: &'a str,
    genesis_commitment: &'a str,
    reference: String,
    duplicate: bool,
}

fn serve(
    stream: &mut TcpStream,
    identity: &Identity,
    token: &[u8],
    store: &mut DurableDeliveryStore,
) -> Result<(), &'static str> {
    let request = match read_request(stream) {
        Ok(request) => request,
        Err(_) => return write_error(stream, 400, "malformed_request"),
    };
    if request.method == b"GET" && request.path == b"/v1/health" {
        if !request.body.is_empty() {
            return write_error(stream, 400, "malformed_request");
        }
        return write_json(
            stream,
            200,
            &HealthResponse {
                status: "healthy",
                chain_id: &identity.chain_id,
                genesis_commitment: &identity.genesis_commitment,
                deployment_revision: &identity.deployment_revision,
                durable_receipts: store.len(),
            },
        );
    }
    let Some(supplied) = request.authorization.strip_prefix(b"Bearer ") else {
        return write_error(stream, 401, "unauthorized");
    };
    if !constant_time_eq(supplied, token) {
        return write_error(stream, 401, "unauthorized");
    }
    if request.method != b"POST" || request.path != b"/v1/deliveries" {
        return write_error(stream, 404, "not_found");
    }
    if request.content_type != b"application/octet-stream" {
        return write_error(stream, 415, "unsupported_media_type");
    }
    let receipt = match store.deliver(&request.request_id, &request.body) {
        Ok(receipt) => receipt,
        Err(DeliveryError::Invalid) => return write_error(stream, 400, "malformed_request"),
        Err(DeliveryError::Conflict) => {
            return write_error(stream, 409, "idempotency_conflict");
        }
        Err(DeliveryError::Capacity) => return write_error(stream, 503, "capacity_exhausted"),
        Err(DeliveryError::Persistence) => {
            return write_error(stream, 503, "persistence_unavailable");
        }
    };
    write_json(
        stream,
        200,
        &DeliveryResponse {
            status: "delivered",
            chain_id: &identity.chain_id,
            genesis_commitment: &identity.genesis_commitment,
            reference: digest_hex(receipt.reference),
            duplicate: receipt.duplicate,
        },
    )
}

struct HttpRequest {
    method: Vec<u8>,
    path: Vec<u8>,
    authorization: Vec<u8>,
    request_id: Vec<u8>,
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
            if offset + 4 > MAX_HEADERS {
                return Err(());
            }
            break offset + 4;
        }
        if bytes.len() > MAX_HEADERS {
            return Err(());
        }
    };
    let header = &bytes[..header_end - 4];
    let mut lines = header.split(|byte| *byte == b'\n').map(trim_cr);
    let mut request_line = lines.next().ok_or(())?.split(|byte| *byte == b' ');
    let method = request_line.next().ok_or(())?.to_vec();
    let path = request_line.next().ok_or(())?.to_vec();
    if request_line.next() != Some(b"HTTP/1.1".as_slice()) || request_line.next().is_some() {
        return Err(());
    }
    let mut authorization = None;
    let mut request_id = None;
    let mut content_type = None;
    let mut content_length = None;
    for line in lines {
        let separator = line.iter().position(|byte| *byte == b':').ok_or(())?;
        let name = &line[..separator];
        let value = trim_ascii(&line[separator + 1..]);
        if name.eq_ignore_ascii_case(b"authorization") {
            if authorization.replace(value.to_vec()).is_some() {
                return Err(());
            }
        } else if name.eq_ignore_ascii_case(b"x-actum-request-id") {
            if request_id.replace(value.to_vec()).is_some() {
                return Err(());
            }
        } else if name.eq_ignore_ascii_case(b"content-type") {
            if content_type.replace(value.to_vec()).is_some() {
                return Err(());
            }
        } else if name.eq_ignore_ascii_case(b"content-length") {
            let length = std::str::from_utf8(value).map_err(|_| ())?.parse().map_err(|_| ())?;
            if content_length.replace(length).is_some() {
                return Err(());
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(());
        }
    }
    let length = content_length.unwrap_or(0_usize);
    if length > MAX_DELIVERY_ARTIFACT_BYTES || bytes.len() - header_end > length {
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
        request_id: request_id.unwrap_or_default(),
        content_type: content_type.unwrap_or_default(),
        body: bytes[header_end..].to_vec(),
    })
}

fn load_token(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err("delivery bearer token must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("delivery bearer token must be private".into());
        }
    }
    let mut token = fs::read(path)?;
    while token.last().is_some_and(u8::is_ascii_whitespace) {
        token.pop();
    }
    if !(32..=256).contains(&token.len()) || token.iter().any(|byte| !byte.is_ascii_graphic()) {
        token.zeroize();
        return Err("delivery bearer token must contain 32-256 graphic ASCII bytes".into());
    }
    Ok(token)
}

fn validate_digest(value: String) -> Result<String, Box<dyn std::error::Error>> {
    if value.len() != 96
        || value.bytes().any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err("network digest must be 96 lowercase hex characters and non-zero".into());
    }
    Ok(value)
}

fn validate_revision(value: String) -> Result<String, Box<dyn std::error::Error>> {
    if value.len() != 40
        || value.bytes().any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err("deployment revision must be a full lowercase Git commit".into());
    }
    Ok(value)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0_u8, |difference, (a, b)| difference | (a ^ b)) == 0
}

fn trim_cr(value: &[u8]) -> &[u8] {
    value.strip_suffix(b"\r").unwrap_or(value)
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

fn digest_hex(value: activechain_protocol_types::Digest384) -> String {
    value.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    status: &'static str,
    code: &'a str,
}

fn write_error(stream: &mut TcpStream, status: u16, code: &str) -> Result<(), &'static str> {
    write_json(stream, status, &ErrorResponse { status: "error", code })
}

fn write_json(
    stream: &mut TcpStream,
    status: u16,
    body: &impl Serialize,
) -> Result<(), &'static str> {
    let body = serde_json::to_vec(body).map_err(|_| "serialize")?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .and_then(|()| stream.write_all(&body))
    .map_err(|_| "write")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(request: Vec<u8>, store: &mut DurableDeliveryStore) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&request).unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).unwrap();
            response
        });
        let (mut server, _) = listener.accept().unwrap();
        serve(
            &mut server,
            &Identity {
                chain_id: "1".repeat(96),
                genesis_commitment: "2".repeat(96),
                deployment_revision: "a".repeat(40),
            },
            b"abcdefghijklmnopqrstuvwxyz012345",
            store,
        )
        .unwrap();
        drop(server);
        client.join().unwrap()
    }

    fn post(token: &str, request_id: &str, body: &[u8]) -> Vec<u8> {
        format!(
            "POST /v1/deliveries HTTP/1.1\r\nAuthorization: Bearer {token}\r\nX-Actum-Request-Id: {request_id}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect()
    }

    #[test]
    fn real_http_path_authenticates_and_recovers_idempotently() {
        let directory = tempfile::tempdir().unwrap();
        let store_path = directory.path().join("store");
        let mut store = DurableDeliveryStore::open(&store_path).unwrap();
        let unauthorized = exchange(post("wrong", "request-1", b"proof"), &mut store);
        assert!(unauthorized.starts_with(b"HTTP/1.1 401"));
        assert!(store.is_empty());

        let first =
            exchange(post("abcdefghijklmnopqrstuvwxyz012345", "request-1", b"proof"), &mut store);
        assert!(first.starts_with(b"HTTP/1.1 200"));
        assert!(
            first
                .windows(b"\"duplicate\":false".len())
                .any(|value| { value == b"\"duplicate\":false" })
        );
        drop(store);

        let mut reopened = DurableDeliveryStore::open(&store_path).unwrap();
        let retry = exchange(
            post("abcdefghijklmnopqrstuvwxyz012345", "request-1", b"proof"),
            &mut reopened,
        );
        assert!(retry.starts_with(b"HTTP/1.1 200"));
        assert!(
            retry
                .windows(b"\"duplicate\":true".len())
                .any(|value| { value == b"\"duplicate\":true" })
        );
        let conflict = exchange(
            post("abcdefghijklmnopqrstuvwxyz012345", "request-1", b"other"),
            &mut reopened,
        );
        assert!(conflict.starts_with(b"HTTP/1.1 409"));
    }
}
