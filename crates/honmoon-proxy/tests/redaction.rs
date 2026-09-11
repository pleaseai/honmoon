//! Hermetic wire-redaction integration tests over cleartext forward-proxy HTTP.
//!
//! `inspect_body` handles absolute-form HTTP requests as well as decrypted TLS,
//! so loopback sockets prove the upstream wire bytes without a TLS client harness.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use honmoon_core::{MappingStore, Policy};
use honmoon_proxy::approval::{ApprovalDecision, ApprovalRegistry};
use honmoon_proxy::gateway::{GatewayState, PiiMode, RedactionState, SignedBodyMode};
use honmoon_proxy::signed_body::BODY_DIGEST_HEADERS;

const SECRET: &str = "sk-ant-api03-cache-stable-abcDEF123456";
const RRN: &str = "670125-1230644";
const SALT: &[u8] = b"proxy-wire-redaction-test-salt";
const SIGV4: &str = "AWS4-HMAC-SHA256 Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
     SignedHeaders=host;x-amz-date, Signature=abc";
/// A SigV4 credential whose `SignedHeaders` list covers the headers the
/// redaction rewrite has to re-frame — what an AWS SDK upload signs.
const SIGV4_SIGNED_FRAMING: &str = "AWS4-HMAC-SHA256 \
     Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
     SignedHeaders=content-encoding;content-length;host;x-amz-date, Signature=abc";

/// A SigV4 credential whose `SignedHeaders` list covers a body-digest header
/// the rewrite strips — and none of the framing headers it re-frames — which is
/// the `Content-MD5` shape of an S3 upload.
const SIGV4_SIGNED_DIGEST: &str = "AWS4-HMAC-SHA256 \
     Credential=AKIA/20260907/us-east-1/s3/aws4_request, \
     SignedHeaders=content-md5;host;x-amz-date, Signature=abc";

/// A presigned SigV4 request target: the signature lives in the query string
/// rather than in an `Authorization` header.
const PRESIGNED_TARGET: &str = "/submit?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA&X-Amz-Expires=60\
     &X-Amz-SignedHeaders=host&X-Amz-Signature=abc";

const MAX_BODY: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
struct CapturedRequest {
    headers: String,
    body: Vec<u8>,
    /// The chunked trailer section, as received (empty when none was sent).
    trailers: String,
}

enum ResponseMode {
    Static(Vec<u8>),
    StaticWithHeaders {
        status: &'static str,
        body: Vec<u8>,
        headers: String,
    },
    EncodedStatic {
        body: Vec<u8>,
        encoding: &'static str,
    },
    EchoBody,
    SplitEchoBody,
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buffer).expect("read upstream request");
        assert!(read > 0, "request ended before headers");
        received.extend_from_slice(&buffer[..read]);
        if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers =
        String::from_utf8(received[..header_end].to_vec()).expect("ASCII request headers");
    if header_value(&headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        let (body, trailers) = read_chunked(stream, &mut received, header_end);
        return CapturedRequest {
            headers,
            body,
            trailers,
        };
    }
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("numeric content length")
            })
        })
        .unwrap_or(0);
    while received.len() < header_end + content_length {
        let read = stream.read(&mut buffer).expect("read upstream body");
        assert!(read > 0, "request ended before body");
        received.extend_from_slice(&buffer[..read]);
    }
    CapturedRequest {
        headers,
        body: received[header_end..header_end + content_length].to_vec(),
        trailers: String::new(),
    }
}

/// Decode a chunked request body starting at `pos`, returning the body bytes
/// and the trailer section that followed the terminating zero-length chunk.
fn read_chunked(
    stream: &mut TcpStream,
    received: &mut Vec<u8>,
    mut pos: usize,
) -> (Vec<u8>, String) {
    let mut body = Vec::new();
    loop {
        let (size_line, next) = read_line(stream, received, pos);
        pos = next;
        let size =
            usize::from_str_radix(size_line.split(';').next().expect("chunk size").trim(), 16)
                .expect("hex chunk size");
        if size == 0 {
            break;
        }
        fill_to(stream, received, pos + size + 2);
        body.extend_from_slice(&received[pos..pos + size]);
        pos += size + 2;
    }
    let mut trailers = String::new();
    loop {
        let (line, next) = read_line(stream, received, pos);
        pos = next;
        if line.is_empty() {
            break;
        }
        trailers.push_str(&line);
        trailers.push_str("\r\n");
    }
    (body, trailers)
}

/// Read one CRLF-terminated line at `pos`, pulling more bytes as needed.
/// Returns the line without its terminator and the offset just past it.
fn read_line(stream: &mut TcpStream, received: &mut Vec<u8>, pos: usize) -> (String, usize) {
    let mut buffer = [0u8; 4096];
    loop {
        if let Some(offset) = received[pos..].windows(2).position(|w| w == b"\r\n") {
            let line =
                String::from_utf8(received[pos..pos + offset].to_vec()).expect("ASCII chunk line");
            return (line, pos + offset + 2);
        }
        let read = stream.read(&mut buffer).expect("read upstream chunk");
        assert!(read > 0, "request ended mid-chunk");
        received.extend_from_slice(&buffer[..read]);
    }
}

/// Read until `received` holds at least `want` bytes.
fn fill_to(stream: &mut TcpStream, received: &mut Vec<u8>, want: usize) {
    let mut buffer = [0u8; 4096];
    while received.len() < want {
        let read = stream.read(&mut buffer).expect("read upstream chunk");
        assert!(read > 0, "request ended mid-chunk");
        received.extend_from_slice(&buffer[..read]);
    }
}

fn start_upstream(mode: ResponseMode) -> (u16, Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    let mode = Arc::new(Mutex::new(mode));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let captured = read_request(&mut stream);
            tx.send(captured.clone()).unwrap();
            match &*mode.lock().unwrap() {
                ResponseMode::Static(body) => {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(body).unwrap();
                }
                ResponseMode::StaticWithHeaders {
                    status,
                    body,
                    headers,
                } => {
                    write!(
                        stream,
                        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(body).unwrap();
                }
                ResponseMode::EncodedStatic { body, encoding } => {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Encoding: {encoding}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(body).unwrap();
                }
                ResponseMode::EchoBody => {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        captured.body.len()
                    )
                    .unwrap();
                    stream.write_all(&captured.body).unwrap();
                }
                ResponseMode::SplitEchoBody => {
                    let split = captured
                        .body
                        .windows(5)
                        .position(|window| window == b"<<hs:")
                        .map(|start| start + 12)
                        .unwrap_or(captured.body.len() / 2);
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                        split
                    )
                    .unwrap();
                    stream.write_all(&captured.body[..split]).unwrap();
                    write!(stream, "\r\n{:x}\r\n", captured.body.len() - split).unwrap();
                    stream.write_all(&captured.body[split..]).unwrap();
                    stream.write_all(b"\r\n0\r\n\r\n").unwrap();
                }
            }
        }
    });
    (port, rx)
}

fn start_proxy(redaction: bool) -> (u16, Option<Arc<MappingStore>>) {
    start_proxy_with_signed_body(redaction, SignedBodyMode::default())
}

fn start_proxy_with_signed_body(
    redaction: bool,
    signed_body: SignedBodyMode,
) -> (u16, Option<Arc<MappingStore>>) {
    let policy = Policy::from_yaml("egress:\n  default: allow\n").unwrap();
    let mut state = GatewayState::new(policy);
    let mappings = if redaction {
        state.redaction = Some(RedactionState::new(SALT.to_vec()).with_signed_body(signed_body));
        Some(Arc::clone(&state.redaction.as_ref().unwrap().mappings))
    } else {
        None
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        honmoon_proxy::gateway::serve_listener_with_state(state, listener);
    });
    wait_for_port(port);
    (port, mappings)
}

fn start_proxy_with_policy(policy_yaml: &str, pii_mode: PiiMode) -> (u16, Arc<ApprovalRegistry>) {
    let policy = Policy::from_yaml(policy_yaml).unwrap();
    let mut state = GatewayState::new(policy);
    state.pii_mode = pii_mode;
    state.redaction = Some(RedactionState::new(SALT.to_vec()));
    let approvals = Arc::clone(&state.approvals);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        honmoon_proxy::gateway::serve_listener_with_state(state, listener);
    });
    wait_for_port(port);
    (port, approvals)
}

fn wait_for_port(port: u16) {
    for _ in 0..250 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("proxy did not listen on {port}");
}

fn raw_proxy_request(proxy_port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

fn proxy_request(
    proxy_port: u16,
    upstream_port: u16,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Vec<u8> {
    proxy_request_to(proxy_port, upstream_port, "/submit", body, extra_headers)
}

/// `proxy_request` with control over the request target, for the cases whose
/// classification lives in the query string (a presigned SigV4 URL).
fn proxy_request_to(
    proxy_port: u16,
    upstream_port: u16,
    target: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let extra = extra_headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    write!(
        stream,
        "POST http://127.0.0.1:{upstream_port}{target} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

fn response_headers(response: &[u8]) -> String {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers")
        + 4;
    String::from_utf8(response[..header_end].to_vec()).expect("ASCII response headers")
}

fn response_body(response: &[u8]) -> Vec<u8> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers")
        + 4;
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let body = &response[header_end..];
    if !headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return body.to_vec();
    }

    let mut decoded = Vec::new();
    let mut rest = body;
    loop {
        let line_end = rest
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size line");
        let size =
            usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap().trim(), 16)
                .unwrap();
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    decoded
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

#[test]
fn wire_redaction_rewrites_secret_and_pii_with_correct_headers() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, _) = start_proxy(true);
    let original = format!("key={SECRET}&rrn={RRN}");

    let response = proxy_request(proxy, upstream, original.as_bytes(), &[]);
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let request = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let text = String::from_utf8(request.body.clone()).unwrap();
    assert!(!text.contains(SECRET));
    assert!(!text.contains(RRN));
    assert!(text.contains("<<hs:"));
    assert_eq!(
        header_value(&request.headers, "content-length"),
        Some(request.body.len().to_string().as_str())
    );
    assert_eq!(
        header_value(&request.headers, "accept-encoding"),
        Some("identity")
    );
}

#[test]
fn rewritten_request_strips_stale_body_integrity_headers() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, _) = start_proxy(true);
    let body = format!("key={SECRET}");

    proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[
            ("Content-MD5", "stale"),
            ("Digest", "sha-256=stale"),
            ("Content-Digest", "sha-256=:stale:"),
            ("Repr-Digest", "sha-256=:stale:"),
            ("Authorization", "preserved"),
        ],
    );
    let request = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    // Read from the constant the strip loop itself iterates, so a validator
    // added there is asserted here without editing this test.
    for name in BODY_DIGEST_HEADERS {
        let name = name.as_str();
        assert_eq!(header_value(&request.headers, name), None, "{name}");
    }
    assert_eq!(
        header_value(&request.headers, "authorization"),
        Some("preserved")
    );
}

#[test]
fn repeated_multi_turn_body_is_byte_identical_on_the_wire() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, _) = start_proxy(true);
    let body = format!("turn one: {SECRET}\nturn two repeats {SECRET}");

    proxy_request(proxy, upstream, body.as_bytes(), &[]);
    proxy_request(proxy, upstream, body.as_bytes(), &[]);
    let first = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(first.body, second.body);
    let first = String::from_utf8(first.body).unwrap();
    assert_eq!(first.matches("<<hs:").count(), 2);
}

// The JSON wire path (`redact_json_with_spans`) does its own occurrence
// selection instead of delegating wholesale to the core tokenizer, so guard the
// cache-stable determinism guarantee (#20) on that path directly: a repeated
// secret in a JSON body must tokenize byte-identically across turns.
#[test]
fn repeated_multi_turn_json_body_is_byte_identical_on_the_wire() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, _) = start_proxy(true);
    let body = format!(r#"{{"turn_one":"{SECRET}","turn_two":"repeat {SECRET}"}}"#);

    let headers = [("Content-Type", "application/json")];
    proxy_request(proxy, upstream, body.as_bytes(), &headers);
    proxy_request(proxy, upstream, body.as_bytes(), &headers);
    let first = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(first.body, second.body);
    let first = String::from_utf8(first.body).unwrap();
    assert_eq!(first.matches("<<hs:").count(), 2);
}

// A partial upload's Content-Range describes the original bytes; redacting would
// change the body length and desynchronize the range, so the request must fail
// open — forwarded byte-identical with no mapping recorded.
#[test]
fn content_range_request_is_forwarded_unredacted() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = format!("chunk {SECRET}");

    proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[("Content-Range", "bytes 0-20/40")],
    );
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(forwarded.body, body.as_bytes());
    assert_eq!(
        header_value(&forwarded.headers, "content-range"),
        Some("bytes 0-20/40")
    );
    assert_eq!(mappings.unwrap().len(), 0);
}

#[test]
fn gzip_request_is_forwarded_as_decoded_redacted_identity_text() {
    use std::io::Write as _;

    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, _) = start_proxy(true);
    let original = format!("compressed key={SECRET}");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();

    proxy_request(
        proxy,
        upstream,
        &compressed,
        &[("Content-Encoding", "gzip")],
    );
    let request = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let text = String::from_utf8(request.body.clone()).unwrap();
    assert!(text.starts_with("compressed key="));
    assert!(text.contains("<<hs:"));
    assert!(!text.contains(SECRET));
    assert_eq!(header_value(&request.headers, "content-encoding"), None);
    assert_eq!(
        header_value(&request.headers, "content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        request.body.len()
    );
}

#[test]
fn response_echo_restores_the_request_secret() {
    let (upstream, captured) = start_upstream(ResponseMode::EchoBody);
    let (proxy, _) = start_proxy(true);
    let original = format!("upstream echo {SECRET}");

    let response = proxy_request(proxy, upstream, original.as_bytes(), &[]);
    let headers = response_headers(&response);
    assert_eq!(header_value(&headers, "content-length"), None);
    assert_eq!(header_value(&headers, "transfer-encoding"), Some("chunked"));
    let request = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        !request
            .body
            .windows(SECRET.len())
            .any(|w| w == SECRET.as_bytes())
    );
    assert_eq!(response_body(&response), original.as_bytes());
}

#[test]
fn detokenized_response_strips_stale_body_validators() {
    let tokenized = honmoon_core::redact(SECRET, SALT, honmoon_core::DEFAULT_MIN_PII_SEVERITY);
    let (upstream, captured) = start_upstream(ResponseMode::StaticWithHeaders {
        status: "200 OK",
        body: tokenized.text.into_bytes(),
        headers: "Content-MD5: stale\r\nDigest: sha-256=stale\r\nContent-Digest: sha-256=:stale:\r\nRepr-Digest: sha-256=:stale:\r\nContent-Range: bytes 0-41/42\r\nETag: \"stale\"\r\n".to_owned(),
    });
    let (proxy, _) = start_proxy(true);
    proxy_request(proxy, upstream, SECRET.as_bytes(), &[]);
    captured.recv_timeout(Duration::from_secs(5)).unwrap();

    let response = proxy_request(proxy, upstream, b"clean", &[]);
    let headers = response_headers(&response);
    for name in ["content-length", "content-range", "etag"] {
        assert_eq!(header_value(&headers, name), None, "{name}");
    }
    for name in BODY_DIGEST_HEADERS {
        let name = name.as_str();
        assert_eq!(header_value(&headers, name), None, "{name}");
    }
    assert_eq!(response_body(&response), SECRET.as_bytes());
}

#[test]
fn partial_content_response_bypasses_detokenization() {
    let tokenized = honmoon_core::redact(SECRET, SALT, honmoon_core::DEFAULT_MIN_PII_SEVERITY);
    let placeholder = tokenized.text.into_bytes();
    let content_range = format!("bytes 0-{}/{}", placeholder.len() - 1, placeholder.len());
    let headers = format!("Content-Range: {content_range}\r\n");
    let (upstream, captured) = start_upstream(ResponseMode::StaticWithHeaders {
        status: "206 Partial Content",
        body: placeholder.clone(),
        headers,
    });
    let (proxy, _) = start_proxy(true);
    proxy_request(proxy, upstream, SECRET.as_bytes(), &[]);
    captured.recv_timeout(Duration::from_secs(5)).unwrap();

    let response = proxy_request(proxy, upstream, b"clean", &[]);
    let response_headers = response_headers(&response);
    assert!(response.starts_with(b"HTTP/1.1 206"));
    assert_eq!(
        header_value(&response_headers, "content-range"),
        Some(content_range.as_str())
    );
    assert_eq!(response_body(&response), placeholder);
}

#[test]
fn response_placeholder_split_across_upstream_chunks_is_restored() {
    let (upstream, _captured) = start_upstream(ResponseMode::SplitEchoBody);
    let (proxy, _) = start_proxy(true);
    let original = format!("split echo {SECRET} suffix");

    let response = proxy_request(proxy, upstream, original.as_bytes(), &[]);
    let headers = response_headers(&response);
    assert_eq!(header_value(&headers, "content-length"), None);
    assert_eq!(header_value(&headers, "transfer-encoding"), Some("chunked"));
    assert_eq!(response_body(&response), original.as_bytes());
}

#[test]
fn chunked_request_is_redacted_and_reframed_with_content_length() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, _) = start_proxy(true);
    let body = format!("chunked key={SECRET}");
    let request = format!(
        "POST http://127.0.0.1:{upstream}/submit HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        body.len(),
        body
    );

    let response = raw_proxy_request(proxy, request.as_bytes());
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let captured = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let text = String::from_utf8(captured.body.clone()).unwrap();
    assert!(text.contains("<<hs:"));
    assert!(!text.contains(SECRET));
    assert_eq!(header_value(&captured.headers, "transfer-encoding"), None);
    assert_eq!(
        header_value(&captured.headers, "content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        captured.body.len()
    );
}

#[test]
fn fail_open_requests_preserve_wire_bytes_and_record_no_mapping() {
    struct Case {
        name: &'static str,
        body: Vec<u8>,
        encoding: Option<&'static str>,
    }

    let cases = vec![
        Case {
            name: "unsupported encoding",
            body: format!("br-labeled {SECRET}").into_bytes(),
            encoding: Some("br"),
        },
        Case {
            name: "malformed gzip",
            body: format!("not-gzip {SECRET}").into_bytes(),
            encoding: Some("gzip"),
        },
        Case {
            name: "non-UTF-8",
            body: {
                let mut body = format!("binary {SECRET} ").into_bytes();
                body.extend_from_slice(b"\xff\xfe");
                body
            },
            encoding: None,
        },
    ];

    for case in cases {
        let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
        let (proxy, mappings) = start_proxy(true);
        let encoding_header = case
            .encoding
            .map(|encoding| format!("Content-Encoding: {encoding}\r\n"))
            .unwrap_or_default();
        let mut request = format!(
            "POST http://127.0.0.1:{upstream}/submit HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\n{encoding_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
            case.body.len()
        )
        .into_bytes();
        request.extend_from_slice(&case.body);

        let response = raw_proxy_request(proxy, &request);
        assert!(response.starts_with(b"HTTP/1.1 200"), "{}", case.name);
        let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(forwarded.body, case.body, "{}", case.name);
        assert_eq!(
            header_value(&forwarded.headers, "content-length"),
            Some(case.body.len().to_string().as_str()),
            "{}",
            case.name
        );
        assert_eq!(
            header_value(&forwarded.headers, "content-encoding"),
            case.encoding,
            "{}",
            case.name
        );
        assert_eq!(mappings.unwrap().len(), 0, "{}", case.name);
    }
}

#[test]
fn over_cap_request_preserves_bytes_and_records_no_mapping() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let mut body = vec![b'x'; MAX_BODY + 1];
    body[..SECRET.len()].copy_from_slice(SECRET.as_bytes());

    let response = proxy_request(proxy, upstream, &body, &[]);
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(forwarded.body, body);
    assert_eq!(
        header_value(&forwarded.headers, "content-length"),
        Some(body.len().to_string().as_str())
    );
    assert_eq!(mappings.unwrap().len(), 0);
}

#[test]
fn gzip_decoded_over_cap_preserves_wire_bytes_and_records_no_mapping() {
    use std::io::Write as _;

    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let mut decoded = vec![b'x'; MAX_BODY + 1];
    decoded[..SECRET.len()].copy_from_slice(SECRET.as_bytes());
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&decoded).unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(compressed.len() < MAX_BODY);

    let response = proxy_request(
        proxy,
        upstream,
        &compressed,
        &[("Content-Encoding", "gzip")],
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(forwarded.body, compressed);
    assert_eq!(
        header_value(&forwarded.headers, "content-encoding"),
        Some("gzip")
    );
    assert_eq!(mappings.unwrap().len(), 0);
}

#[test]
fn compressed_response_bypasses_detokenization_and_preserves_framing() {
    use std::io::Write as _;

    let tokenized = honmoon_core::redact(SECRET, SALT, honmoon_core::DEFAULT_MIN_PII_SEVERITY);
    let placeholder = tokenized.text.into_bytes();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&placeholder).unwrap();
    let gzip = encoder.finish().unwrap();

    for (name, body) in [("marked-only", placeholder), ("valid-gzip", gzip)] {
        let (upstream, captured) = start_upstream(ResponseMode::EncodedStatic {
            body: body.clone(),
            encoding: "gzip",
        });
        let (proxy, _) = start_proxy(true);
        proxy_request(proxy, upstream, SECRET.as_bytes(), &[]);
        captured.recv_timeout(Duration::from_secs(5)).unwrap();

        let response = proxy_request(proxy, upstream, b"clean", &[]);
        let headers = response_headers(&response);
        assert_eq!(
            header_value(&headers, "content-encoding"),
            Some("gzip"),
            "{name}"
        );
        assert_eq!(
            header_value(&headers, "content-length")
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            body.len(),
            "{name}"
        );
        assert_eq!(response_body(&response), body, "{name}");
    }
}

#[test]
fn quoted_and_unquoted_identical_json_pii_redacts_only_quoted_occurrence() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = br#"{"card":4111111111111111,"note":"4111111111111111"}"#;

    proxy_request(
        proxy,
        upstream,
        body,
        &[("Content-Type", "application/json")],
    );
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&forwarded.body).unwrap();
    assert_eq!(parsed["card"], serde_json::json!(4111111111111111u64));
    assert!(parsed["note"].as_str().unwrap().starts_with("<<hs:"));
    assert_eq!(mappings.unwrap().len(), 1);
}

#[test]
fn unquoted_numeric_json_pii_is_not_rewritten() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = br#"{"card":4111111111111111,"email":"user@example.com"}"#;

    proxy_request(
        proxy,
        upstream,
        body,
        &[("Content-Type", "application/json")],
    );
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&forwarded.body).unwrap();
    assert_eq!(parsed["card"], serde_json::json!(4111111111111111u64));
    assert_ne!(parsed["email"], "user@example.com");
    assert!(parsed["email"].as_str().unwrap().starts_with("<<hs:"));
    assert_eq!(mappings.unwrap().len(), 1);
}

#[test]
fn block_mode_allow_forwards_redacted_body() {
    let policy = "egress:\n  default: allow\n";
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, _) = start_proxy_with_policy(policy, PiiMode::Block);
    let body = format!("allowed rrn={RRN}");

    let response = proxy_request(proxy, upstream, body.as_bytes(), &[]);
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded =
        String::from_utf8(captured.recv_timeout(Duration::from_secs(5)).unwrap().body).unwrap();
    assert!(!forwarded.contains(RRN));
    assert!(forwarded.contains("<<hs:"));
}

#[test]
fn block_mode_pause_approved_forwards_redacted_body() {
    let policy = "egress:\n  default: allow\nrules:\n  - name: review-rrn\n    endpoint: '*'\n    condition: \"pii.count > 0\"\n    verdict: pause\n";
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, approvals) = start_proxy_with_policy(policy, PiiMode::Block);
    let body = format!("paused rrn={RRN}");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        tx.send(proxy_request(proxy, upstream, body.as_bytes(), &[]))
            .unwrap();
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let pending = loop {
        if let Some(pending) = approvals.pending().first().cloned() {
            break pending;
        }
        assert!(Instant::now() < deadline, "approval did not appear");
        thread::sleep(Duration::from_millis(20));
    };
    approvals
        .resolve(pending.id, ApprovalDecision::Approve)
        .expect("approval exists");

    let response = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded =
        String::from_utf8(captured.recv_timeout(Duration::from_secs(5)).unwrap().body).unwrap();
    assert!(!forwarded.contains(RRN));
    assert!(forwarded.contains("<<hs:"));
}

#[test]
fn block_mode_deny_does_not_forward() {
    let policy = "egress:\n  default: allow\nrules:\n  - name: block-rrn\n    endpoint: '*'\n    condition: \"pii.count > 0\"\n    verdict: deny\n";
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, _) = start_proxy_with_policy(policy, PiiMode::Block);
    let body = format!("denied rrn={RRN}");

    let response = proxy_request(proxy, upstream, body.as_bytes(), &[]);
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert!(captured.recv_timeout(Duration::from_millis(250)).is_err());
}

#[test]
fn redaction_is_off_by_default() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, _) = start_proxy(false);
    let body = format!("raw key={SECRET}");

    proxy_request(proxy, upstream, body.as_bytes(), &[]);
    let request = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(request.body, body.as_bytes());
    assert_eq!(header_value(&request.headers, "accept-encoding"), None);
}

// A SigV4 `Authorization` covers the payload hash, so a rewritten body would be
// rejected upstream with an opaque signature error. The default `block` mode
// refuses the request locally instead — the secret never leaves the host.
#[test]
fn signed_body_request_with_secret_is_blocked_by_default() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = format!("key={SECRET}");

    let response = proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[("Authorization", SIGV4)],
    );
    let headers = response_headers(&response);
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert_eq!(
        header_value(&headers, "x-honmoon-reason"),
        Some("signed-body-redaction")
    );
    assert!(String::from_utf8_lossy(&response).contains("--signed-body forward"));
    assert!(captured.recv_timeout(Duration::from_millis(250)).is_err());
    assert_eq!(mappings.unwrap().len(), 0);
}

// Forward mode must reproduce the bytes the client signed, `Accept-Encoding`
// included — several SigV4 signers list it in `SignedHeaders`, so overwriting it
// with the usual `identity` negotiation would trade one signature failure for
// another.
#[test]
fn signed_body_request_with_secret_is_forwarded_unredacted_in_forward_mode() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy_with_signed_body(true, SignedBodyMode::Forward);
    let body = format!("key={SECRET}");

    let response = proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[("Authorization", SIGV4), ("Accept-Encoding", "gzip, br")],
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(forwarded.body, body.as_bytes());
    assert_eq!(
        header_value(&forwarded.headers, "authorization"),
        Some(SIGV4)
    );
    assert_eq!(
        header_value(&forwarded.headers, "content-length"),
        Some(body.len().to_string().as_str())
    );
    assert_eq!(
        header_value(&forwarded.headers, "accept-encoding"),
        Some("gzip, br")
    );

    // A client that sent no Accept-Encoding must not gain one either.
    proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[("Authorization", SIGV4)],
    );
    let bare = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(header_value(&bare.headers, "accept-encoding"), None);
    assert_eq!(mappings.unwrap().len(), 0);
}

// RFC 9421 lets the `Content-Digest` a signature covers ride in a trailer
// rather than a header. Buffering the body for the PII scan must hand that
// trailer back, or `forward` mode forwards a request the client never signed
// and earns the upstream signature rejection the mode exists to avoid (#82).
#[test]
fn signed_body_request_keeps_its_digest_trailer_in_forward_mode() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy_with_signed_body(true, SignedBodyMode::Forward);
    let body = format!("key={SECRET}");
    let digest = "sha-256=:ZGlnZXN0LW92ZXItdGhlLXNpZ25lZC1ib2R5:";

    let request = format!(
        "POST http://127.0.0.1:{upstream}/submit HTTP/1.1\r\n\
         Host: 127.0.0.1:{upstream}\r\n\
         Signature-Input: sig1=(\"@method\" \"content-digest\")\r\n\
         Signature: sig1=:c2lnbmF0dXJl:\r\n\
         Trailer: Content-Digest\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n\
         {:x}\r\n{body}\r\n0\r\nContent-Digest: {digest}\r\n\r\n",
        body.len()
    );
    let response = raw_proxy_request(proxy, request.as_bytes());
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(forwarded.body, body.as_bytes());
    assert_eq!(
        header_value(&forwarded.trailers, "content-digest"),
        Some(digest),
        "the signed digest trailer must reach the upstream"
    );
    assert_eq!(mappings.unwrap().len(), 0);
}

// The `identity` negotiation must not leak onto the common 'signed request,
// nothing to redact' path either: the client's `Accept-Encoding` may be one of
// the headers it signed.
#[test]
fn signed_body_request_without_secret_keeps_client_accept_encoding() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = b"key=nothing-to-redact";

    let response = proxy_request(
        proxy,
        upstream,
        body,
        &[("Authorization", SIGV4), ("Accept-Encoding", "gzip")],
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(forwarded.body, body);
    assert_eq!(
        header_value(&forwarded.headers, "accept-encoding"),
        Some("gzip")
    );
    assert_eq!(mappings.unwrap().len(), 0);
}

// A bare hex `x-amz-content-sha256` is an integrity header, not a signature:
// with no SigV4 authentication on the request, nothing says the bytes are
// signed, so redaction stays on rather than refusing the request (#81).
#[test]
fn bare_payload_hash_request_is_still_redacted() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = format!("key={SECRET}");

    let response = proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[("x-amz-content-sha256", &"a".repeat(64))],
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let text = String::from_utf8(forwarded.body).unwrap();
    assert!(!text.contains(SECRET));
    assert!(text.contains("<<hs:"));
    assert_eq!(mappings.unwrap().len(), 1);
}

// A standard S3 presigned upload signs the request, not the payload — its
// canonical request declares `UNSIGNED-PAYLOAD` — so the secret in its body is
// redacted and the upload goes through instead of earning a `403` (#81).
#[test]
fn presigned_sigv4_upload_without_a_payload_hash_is_still_redacted() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = format!("key={SECRET}");

    let response = proxy_request_to(proxy, upstream, PRESIGNED_TARGET, body.as_bytes(), &[]);
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let text = String::from_utf8(forwarded.body).unwrap();
    assert!(!text.contains(SECRET));
    assert!(text.contains("<<hs:"));
    assert_eq!(mappings.unwrap().len(), 1);
}

// `forward` is the same escape hatch for the presigned carrier: the bytes the
// client signed reach the upstream untouched, whichever carrier classified the
// request as body-signed.
#[test]
fn presigned_sigv4_upload_with_a_payload_hash_is_forwarded_unredacted_in_forward_mode() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy_with_signed_body(true, SignedBodyMode::Forward);
    let body = format!("key={SECRET}");

    let response = proxy_request_to(
        proxy,
        upstream,
        PRESIGNED_TARGET,
        body.as_bytes(),
        &[("x-amz-content-sha256", &"a".repeat(64))],
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(forwarded.body, body.as_bytes());
    assert_eq!(
        header_value(&forwarded.headers, "content-length"),
        Some(body.len().to_string().as_str())
    );
    assert_eq!(mappings.unwrap().len(), 0);
}

// The presigned URL that *does* bind its payload — a hex `x-amz-content-sha256`
// alongside the query signature — still takes the fail-closed decision.
#[test]
fn presigned_sigv4_upload_with_a_payload_hash_is_blocked_by_default() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = format!("key={SECRET}");

    let response = proxy_request_to(
        proxy,
        upstream,
        PRESIGNED_TARGET,
        body.as_bytes(),
        &[("x-amz-content-sha256", &"a".repeat(64))],
    );
    let headers = response_headers(&response);
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert_eq!(
        header_value(&headers, "x-honmoon-reason"),
        Some("signed-body-redaction")
    );
    assert!(captured.recv_timeout(Duration::from_millis(250)).is_err());
    assert_eq!(mappings.unwrap().len(), 0);
}

#[test]
fn signed_body_request_without_secret_is_forwarded_untouched() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = b"key=nothing-to-redact";

    let response = proxy_request(proxy, upstream, body, &[("Authorization", SIGV4)]);
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(forwarded.body, body);
    assert_eq!(
        header_value(&forwarded.headers, "authorization"),
        Some(SIGV4)
    );
    assert_eq!(mappings.unwrap().len(), 0);
}

// `UNSIGNED-PAYLOAD` says the signature does not cover the body, so redaction
// stays on for the common S3 upload path.
#[test]
fn unsigned_payload_sigv4_request_is_still_redacted() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = format!("key={SECRET}");

    let response = proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[
            ("Authorization", SIGV4),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ],
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let text = String::from_utf8(forwarded.body).unwrap();
    assert!(!text.contains(SECRET));
    assert!(text.contains("<<hs:"));
    assert_eq!(mappings.unwrap().len(), 1);
}

// `UNSIGNED-PAYLOAD` only says the payload is unsigned — the `Authorization`
// may still cover headers such as `Accept-Encoding` in `SignedHeaders`.
// Redaction must stay on (the body is not signed), but the identity
// negotiation that would otherwise overwrite a signed `Accept-Encoding` must
// not fire for this request either.
#[test]
fn unsigned_payload_sigv4_request_keeps_client_accept_encoding_while_redacted() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = format!("key={SECRET}");

    let response = proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[
            ("Authorization", SIGV4),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
            ("Accept-Encoding", "gzip"),
        ],
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        header_value(&forwarded.headers, "accept-encoding"),
        Some("gzip")
    );
    let text = String::from_utf8(forwarded.body).unwrap();
    assert!(!text.contains(SECRET));
    assert!(text.contains("<<hs:"));
    assert_eq!(mappings.unwrap().len(), 1);
}

// `UNSIGNED-PAYLOAD` leaves the body redactable, but SigV4 signs headers even
// when it does not sign the payload — and re-framing the redacted body rewrites
// `Content-Length`, which an SDK upload lists in `SignedHeaders`. Forwarding it
// would break the signature just as surely as rewriting a signed body, so it
// takes the same fail-closed decision.
#[test]
fn unsigned_payload_upload_signing_content_length_is_blocked_by_default() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = format!("key={SECRET}");

    let response = proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[
            ("Authorization", SIGV4_SIGNED_FRAMING),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ],
    );
    let headers = response_headers(&response);
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert_eq!(
        header_value(&headers, "x-honmoon-reason"),
        Some("signed-header-redaction")
    );
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("content-length"));
    // The request carries no Content-Encoding, so the rewrite would not drop
    // one and the signature over it is not what breaks.
    assert!(!text.contains("content-encoding"));
    assert!(text.contains("--signed-body forward"));
    assert!(captured.recv_timeout(Duration::from_millis(250)).is_err());
    assert_eq!(mappings.unwrap().len(), 0);
}

// Dropping the client's `Content-Encoding` breaks a signature over it the same
// way, and the block message names every header the rewrite would change.
#[test]
fn unsigned_payload_upload_signing_content_encoding_is_blocked_by_default() {
    use std::io::Write as _;

    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let original = format!("compressed key={SECRET}");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();

    let response = proxy_request(
        proxy,
        upstream,
        &compressed,
        &[
            ("Authorization", SIGV4_SIGNED_FRAMING),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
            ("Content-Encoding", "gzip"),
        ],
    );
    assert!(response.starts_with(b"HTTP/1.1 403"));
    let text = String::from_utf8_lossy(&response);
    assert!(text.contains("content-length"));
    assert!(text.contains("content-encoding"));
    assert!(captured.recv_timeout(Duration::from_millis(250)).is_err());
    assert_eq!(mappings.unwrap().len(), 0);
}

// The rewrite strips the stale body-digest validators as well as re-framing,
// and `UNSIGNED-PAYLOAD` keeps the body-signed branch from firing — so a SigV4
// upload that lists `content-md5` in `SignedHeaders` would have that header
// removed under a signature covering it. Stripping a signed header breaks the
// signature exactly as re-framing one does, so it takes the same decision.
#[test]
fn unsigned_payload_upload_signing_content_md5_is_blocked_by_default() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = format!("key={SECRET}");

    let response = proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[
            ("Authorization", SIGV4_SIGNED_DIGEST),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
            ("Content-MD5", "Q2hlY2sgSW50ZWdyaXR5IQ=="),
        ],
    );
    let headers = response_headers(&response);
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert_eq!(
        header_value(&headers, "x-honmoon-reason"),
        Some("signed-header-redaction")
    );
    let reason = String::from_utf8(response_body(&response)).unwrap();
    assert!(reason.contains("content-md5"), "{reason}");
    // The credential does not cover `Content-Length`, so the re-framing the
    // rewrite would do is not what breaks this signature.
    assert!(!reason.contains("content-length"), "{reason}");
    assert!(reason.contains("--signed-body forward"));
    assert!(captured.recv_timeout(Duration::from_millis(250)).is_err());
    assert_eq!(mappings.unwrap().len(), 0);
}

// Only the digest headers the request actually carries count. A `SignedHeaders`
// list may name a header the client never sent, and the rewrite cannot break
// what it does not strip — refusing on that would cost a `403` for nothing.
#[test]
fn a_signed_digest_header_the_request_never_sent_does_not_block() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy(true);
    let body = format!("key={SECRET}");

    let response = proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[
            ("Authorization", SIGV4_SIGNED_DIGEST),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ],
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let text = String::from_utf8(forwarded.body).unwrap();
    assert!(!text.contains(SECRET));
    assert!(text.contains("<<hs:"));
    assert_eq!(mappings.unwrap().len(), 1);
}

// `forward` is the escape hatch for the digest half too, and it is the half
// that forwards a secret: the client's `Content-MD5` reaches the upstream
// describing the bytes it still covers, unredacted, rather than being stripped.
#[test]
fn a_digest_signed_request_is_forwarded_unredacted_in_forward_mode() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy_with_signed_body(true, SignedBodyMode::Forward);
    let body = format!("key={SECRET}");
    let digest = "Q2hlY2sgSW50ZWdyaXR5IQ==";

    let response = proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[
            ("Authorization", SIGV4_SIGNED_DIGEST),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
            ("Content-MD5", digest),
        ],
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(forwarded.body, body.as_bytes());
    assert_eq!(
        header_value(&forwarded.headers, "content-md5"),
        Some(digest),
        "the signed validator is preserved, not stripped"
    );
    assert_eq!(mappings.unwrap().len(), 0);
}

// `forward` is the same escape hatch it is for a body-signed request: the
// client's bytes and framing headers reach the upstream exactly as signed, and
// no mapping is recorded for a substitution that never happened.
#[test]
fn header_signed_request_is_forwarded_unredacted_in_forward_mode() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let (proxy, mappings) = start_proxy_with_signed_body(true, SignedBodyMode::Forward);
    let body = format!("key={SECRET}");

    let response = proxy_request(
        proxy,
        upstream,
        body.as_bytes(),
        &[
            ("Authorization", SIGV4_SIGNED_FRAMING),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ],
    );
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(forwarded.body, body.as_bytes());
    assert_eq!(
        header_value(&forwarded.headers, "content-length"),
        Some(body.len().to_string().as_str())
    );
    assert_eq!(mappings.unwrap().len(), 0);
}
