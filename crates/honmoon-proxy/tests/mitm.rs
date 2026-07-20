//! Hermetic TLS-termination (MITM) integration test.
//!
//! Proves Phase 5's data-plane milestone: with interception enabled, the proxy
//! terminates the client's TLS, decrypts an HTTPS request body, scans it, and
//! records a PII finding to the audit log — the live data source the Tier-1
//! detector needed. No external processes: an in-process CA, a loopback
//! upstream, and a `tokio-rustls` client that trusts the CA.

use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use honmoon_core::{AuditLog, Decision, Policy};
use honmoon_proxy::approval::{ApprovalDecision, ApprovalRegistry};
use honmoon_proxy::ca::CaMaterial;
use honmoon_proxy::gateway::{GatewayState, InterceptPolicy, PiiMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// A structurally valid, checksum-valid RRN (used in `honmoon-core` pii tests).
const VALID_RRN: &str = "670125-1230644";

const DENY_PII_POLICY: &str = "\
egress:
  default: allow
rules:
  - name: block-rrn
    endpoint: '*'
    condition: \"pii.types.exists(type, type == 'RRN')\"
    verdict: deny
";

const PAUSE_PII_POLICY: &str = "\
egress:
  default: allow
rules:
  - name: review-rrn
    endpoint: '*'
    condition: \"pii.types.exists(type, type == 'RRN')\"
    verdict: pause
";

fn rrn_request() -> Vec<u8> {
    let body = format!("form field with rrn={VALID_RRN} inside");
    format!(
        "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

/// An upstream that accepts a connection and immediately drops it, so the
/// proxy's upstream TLS handshake fails fast (→ 502). The audit finding is
/// recorded before the upstream leg, so this is all the test needs.
fn start_dropping_upstream() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream); // close immediately
        }
    });
    port
}

/// A loopback TCP listener that keeps the upstream connection open long enough
/// for the proxy to finish its TLS attempt. Enforcing deny happens before that
/// attempt, while detect-only forwarding reaches it and eventually yields 502.
fn start_hanging_upstream() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(_stream) = stream else { continue };
            thread::sleep(Duration::from_secs(1));
        }
    });
    port
}

fn start_proxy(state: GatewayState) -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        honmoon_proxy::gateway::serve_listener_with_state(state, listener);
    });
    for _ in 0..250 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return port;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("proxy did not start listening on {port}");
}

/// Read an HTTP response head (`\r\n\r\n`) from an async stream.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while stream
        .read(&mut byte)
        .await
        .map(|n| n == 1)
        .unwrap_or(false)
    {
        out.push(byte[0]);
        if out.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Build a client TLS config that trusts only the given CA certificate (PEM).
fn client_config(ca_cert_pem: &str) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_cert_pem.as_bytes()) {
        roots
            .add(cert.expect("valid CA cert"))
            .expect("add CA to roots");
    }
    ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Run an intercepted HTTPS request through the proxy and return the inner HTTP
/// response together with the shared audit/approval state.
fn start_intercepted_request(
    policy_yaml: &str,
    pii_mode: PiiMode,
    upstream: u16,
    request: Vec<u8>,
) -> (mpsc::Receiver<String>, Arc<AuditLog>, Arc<ApprovalRegistry>) {
    let audit = Arc::new(AuditLog::new(1024));
    let approvals = Arc::new(ApprovalRegistry::new());
    let policy = Policy::from_yaml(policy_yaml).unwrap();
    let ca = CaMaterial::generate().unwrap();
    let ca_cert_pem = ca.cert_pem.clone();

    let state = GatewayState {
        policy: Arc::new(policy),
        audit: audit.clone(),
        approvals: approvals.clone(),
        pause_timeout: Duration::from_secs(10),
        ca: Arc::new(ca),
        intercept: InterceptPolicy::All,
        pii_mode,
    };
    let proxy_port = start_proxy(state);
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let response = runtime.block_on(async move {
            // 1. Open a CONNECT tunnel to the host allowed by the host-level gate.
            let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
            let connect = format!(
                "CONNECT localhost:{upstream} HTTP/1.1\r\nHost: localhost:{upstream}\r\n\r\n"
            );
            tcp.write_all(connect.as_bytes()).await.unwrap();
            let established = read_head(&mut tcp).await;
            assert!(
                established.starts_with("HTTP/1.1 200"),
                "tunnel not established: {established:?}"
            );

            // 2. Complete a real TLS handshake with the proxy's minted leaf.
            let connector = TlsConnector::from(Arc::new(client_config(&ca_cert_pem)));
            let server_name = ServerName::try_from("localhost").unwrap();
            let mut tls = connector
                .connect(server_name, tcp)
                .await
                .expect("TLS handshake through the terminating proxy");

            // 3. Send the request over the decrypted channel and read its response.
            tls.write_all(&request).await.unwrap();
            let mut response = Vec::new();
            let _ = tls.read_to_end(&mut response).await;
            String::from_utf8_lossy(&response).into_owned()
        });
        tx.send(response).unwrap();
    });
    (rx, audit, approvals)
}

fn intercepted_request(
    policy_yaml: &str,
    pii_mode: PiiMode,
    upstream: u16,
    request: Vec<u8>,
) -> (String, Arc<AuditLog>, Arc<ApprovalRegistry>) {
    let (rx, audit, approvals) =
        start_intercepted_request(policy_yaml, pii_mode, upstream, request);
    let response = rx
        .recv_timeout(Duration::from_secs(15))
        .expect("intercepted request completed");
    (response, audit, approvals)
}

/// Run a detect-only request against a dropping upstream and report whether the
/// decrypted body produced an RRN audit finding.
fn rrn_audited_for(request: Vec<u8>) -> bool {
    let policy = "egress:\n  default: deny\n  allow:\n    - localhost\n";
    let (response, audit, _) =
        intercepted_request(policy, PiiMode::Detect, start_dropping_upstream(), request);
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "detect-only request should reach the dropping upstream: {response:?}"
    );

    audit.recent(50).iter().any(|e| {
        e.facts
            .pii
            .as_ref()
            .is_some_and(|p| p.count > 0 && p.types.iter().any(|t| t == "RRN"))
    })
}

#[test]
fn terminates_tls_and_detects_pii_in_body() {
    assert!(
        rrn_audited_for(rrn_request()),
        "expected an audit event with an RRN PII finding"
    );
}

#[test]
fn block_mode_denies_rrn_over_intercepted_tls() {
    let (response, audit, approvals) = intercepted_request(
        DENY_PII_POLICY,
        PiiMode::Block,
        start_hanging_upstream(),
        rrn_request(),
    );

    assert!(
        response.starts_with("HTTP/1.1 403"),
        "expected inline 403 for RRN: {response:?}"
    );
    assert!(approvals.is_empty());
    let events = audit.recent(50);
    assert!(events.iter().any(|event| {
        event.decision == Decision::Denied
            && event.rule.as_deref() == Some("block-rrn")
            && event
                .facts
                .pii
                .as_ref()
                .is_some_and(|pii| pii.types.iter().any(|kind| kind == "RRN"))
    }));
}

#[test]
fn detect_mode_audits_but_does_not_deny_rrn() {
    let (response, audit, _) = intercepted_request(
        DENY_PII_POLICY,
        PiiMode::Detect,
        start_dropping_upstream(),
        rrn_request(),
    );

    assert!(
        response.starts_with("HTTP/1.1 502"),
        "detect-only mode must forward instead of returning policy 403: {response:?}"
    );
    let events = audit.recent(50);
    assert!(events.iter().any(|event| {
        event.decision == Decision::Allowed
            && event.rule.as_deref() == Some("block-rrn")
            && event
                .facts
                .pii
                .as_ref()
                .is_some_and(|pii| pii.types.iter().any(|kind| kind == "RRN"))
    }));
}

#[test]
fn block_mode_pauses_rrn_until_approved() {
    let (response_rx, audit, approvals) = start_intercepted_request(
        PAUSE_PII_POLICY,
        PiiMode::Block,
        start_hanging_upstream(),
        rrn_request(),
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let pending = loop {
        if let Some(pending) = approvals.pending().first().cloned() {
            break pending;
        }
        assert!(
            Instant::now() < deadline,
            "PII pause did not enter approval queue"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(pending.rule.as_deref(), Some("review-rrn"));
    assert!(pending.summary.contains("RRN"));
    assert!(
        approvals
            .resolve(pending.id, ApprovalDecision::Approve)
            .is_some()
    );

    let response = response_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("approved request completed");
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "approved PII request was not forwarded to upstream: {response:?}"
    );
    let events = audit.recent(50);
    assert!(events.iter().any(|event| {
        event.decision == Decision::Paused
            && event.rule.as_deref() == Some("review-rrn")
            && event.facts.pii.is_some()
    }));
    assert!(events.iter().any(|event| {
        event.decision == Decision::Approved
            && event.rule.as_deref() == Some("review-rrn")
            && event.facts.pii.is_some()
    }));
}

/// Omitting `Content-Length` (chunked transfer encoding) must not bypass the
/// scan: unknown-length bodies are buffered up to the cap and inspected too.
#[test]
fn detects_pii_in_chunked_body_without_content_length() {
    let body = format!("form field with rrn={VALID_RRN} inside");
    let request = format!(
        "POST /submit HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        body.len(),
        body
    );
    assert!(
        rrn_audited_for(request.into_bytes()),
        "expected an RRN PII finding for a chunked body (no Content-Length)"
    );
}

/// Compressing the body (`Content-Encoding: gzip`) must not bypass the scan:
/// supported encodings are decoded (capped) before PII detection.
#[test]
fn detects_pii_in_gzip_compressed_body() {
    use std::io::Write as _;

    let body = format!("form field with rrn={VALID_RRN} inside");
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(body.as_bytes()).unwrap();
    let compressed = enc.finish().unwrap();

    let mut request = format!(
        "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        compressed.len()
    )
    .into_bytes();
    request.extend_from_slice(&compressed);

    assert!(
        rrn_audited_for(request),
        "expected an RRN PII finding for a gzip-compressed body"
    );
}

/// The `Content-Encoding` header is untrusted client input: a *plaintext* body
/// mislabeled as gzip must not evade the scan — decode failure falls back to
/// scanning the raw bytes.
#[test]
fn detects_pii_when_encoding_is_mislabeled() {
    let body = format!("plaintext with rrn={VALID_RRN} but a lying header");
    let request = format!(
        "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    assert!(
        rrn_audited_for(request.into_bytes()),
        "expected an RRN PII finding for a plaintext body mislabeled as gzip"
    );
}

/// An *unsupported* encoding we can't decode (`br`) must not skip the scan for
/// a plaintext body either — the raw bytes are scanned, so mislabeling with an
/// unknown codec can't evade detection.
#[test]
fn detects_pii_under_unsupported_encoding_label() {
    let body = format!("plaintext with rrn={VALID_RRN} claiming brotli");
    let request = format!(
        "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Encoding: br\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    assert!(
        rrn_audited_for(request.into_bytes()),
        "expected an RRN PII finding for a plaintext body labeled Content-Encoding: br"
    );
}

const DENY_SUBMIT_PATH_POLICY: &str = "\
egress:
  default: allow
rules:
  - name: block-submit-path
    endpoint: '*'
    condition: \"http.path == '/submit'\"
    verdict: deny
";

/// An uninspectable (non-UTF-8) body must not bypass HTTP-metadata rules: the
/// policy engine still runs — with the `pii` facts absent, so unscanned content
/// can never satisfy a `pii.count > 0` condition — and a path/method/size rule
/// denies the request even though its content was never scanned.
#[test]
fn block_mode_enforces_http_rules_on_uninspected_body() {
    let mut body = b"binary \xFF\xFF payload".to_vec();
    let mut request = format!(
        "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.append(&mut body);

    let (response, audit, approvals) = intercepted_request(
        DENY_SUBMIT_PATH_POLICY,
        PiiMode::Block,
        start_hanging_upstream(),
        request,
    );

    assert!(
        response.starts_with("HTTP/1.1 403"),
        "expected 403 from the path rule despite the uninspectable body: {response:?}"
    );
    assert!(approvals.is_empty());
    let events = audit.recent(50);
    assert!(events.iter().any(|event| {
        event.decision == Decision::Denied && event.rule.as_deref() == Some("block-submit-path")
    }));
}
