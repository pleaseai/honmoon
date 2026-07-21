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
use honmoon_proxy::gateway::{GatewayState, PiiMode, RedactionState};

const SECRET: &str = "sk-ant-api03-cache-stable-abcDEF123456";
const RRN: &str = "670125-1230644";
const SALT: &[u8] = b"proxy-wire-redaction-test-salt";

const MAX_BODY: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
struct CapturedRequest {
    headers: String,
    body: Vec<u8>,
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
    let policy = Policy::from_yaml("egress:\n  default: allow\n").unwrap();
    let mut state = GatewayState::new(policy);
    let mappings = if redaction {
        state.redaction = Some(RedactionState::new(SALT.to_vec()));
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
        "POST http://127.0.0.1:{upstream_port}/submit HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
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
    for name in ["content-md5", "digest", "content-digest", "repr-digest"] {
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
    for name in [
        "content-length",
        "content-md5",
        "digest",
        "content-digest",
        "repr-digest",
        "content-range",
        "etag",
    ] {
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
