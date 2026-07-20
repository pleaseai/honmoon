//! Hermetic wire-redaction integration tests over cleartext forward-proxy HTTP.
//!
//! `inspect_body` handles absolute-form HTTP requests as well as decrypted TLS,
//! so loopback sockets prove the upstream wire bytes without a TLS client harness.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use honmoon_core::Policy;
use honmoon_proxy::gateway::{GatewayState, RedactionState};

const SECRET: &str = "sk-ant-api03-cache-stable-abcDEF123456";
const RRN: &str = "670125-1230644";
const SALT: &[u8] = b"proxy-wire-redaction-test-salt";

#[derive(Clone, Debug)]
struct CapturedRequest {
    headers: String,
    body: Vec<u8>,
}

enum ResponseMode {
    Static(Vec<u8>),
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

fn start_proxy(redaction: bool) -> u16 {
    let policy = Policy::from_yaml("egress:\n  default: allow\n").unwrap();
    let mut state = GatewayState::new(policy);
    if redaction {
        state.redaction = Some(RedactionState::new(SALT.to_vec()));
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        honmoon_proxy::gateway::serve_listener_with_state(state, listener);
    });
    wait_for_port(port);
    port
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
    let proxy = start_proxy(true);
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
fn repeated_multi_turn_body_is_byte_identical_on_the_wire() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let proxy = start_proxy(true);
    let body = format!("turn one: {SECRET}\nturn two repeats {SECRET}");

    proxy_request(proxy, upstream, body.as_bytes(), &[]);
    proxy_request(proxy, upstream, body.as_bytes(), &[]);
    let first = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(first.body, second.body);
    let first = String::from_utf8(first.body).unwrap();
    assert_eq!(first.matches("<<hs:").count(), 2);
}

#[test]
fn gzip_request_is_forwarded_as_decoded_redacted_identity_text() {
    use std::io::Write as _;

    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let proxy = start_proxy(true);
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
    let proxy = start_proxy(true);
    let original = format!("upstream echo {SECRET}");

    let response = proxy_request(proxy, upstream, original.as_bytes(), &[]);
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
fn response_placeholder_split_across_upstream_chunks_is_restored() {
    let (upstream, _captured) = start_upstream(ResponseMode::SplitEchoBody);
    let proxy = start_proxy(true);
    let original = format!("split echo {SECRET} suffix");

    let response = proxy_request(proxy, upstream, original.as_bytes(), &[]);
    assert_eq!(response_body(&response), original.as_bytes());
}

#[test]
fn redaction_is_off_by_default() {
    let (upstream, captured) = start_upstream(ResponseMode::Static(b"ok".to_vec()));
    let proxy = start_proxy(false);
    let body = format!("raw key={SECRET}");

    proxy_request(proxy, upstream, body.as_bytes(), &[]);
    let request = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(request.body, body.as_bytes());
    assert_eq!(header_value(&request.headers, "accept-encoding"), None);
}
