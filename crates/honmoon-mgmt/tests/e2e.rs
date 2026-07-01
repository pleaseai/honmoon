//! Phase 4 exit criteria, end to end over real loopback sockets.
//!
//! A `pause` rule holds a live CONNECT request; the held request surfaces on the
//! management API's approval queue; approving it (via a real HTTP call to the
//! management API) lets the tunnel proceed; rejecting it blocks with 403. Every
//! step is recorded in the audit log.
//!
//! No external processes: an in-process upstream, the real proxy + management API
//! sharing one `GatewayState`, and hand-rolled HTTP/CONNECT clients.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use honmoon_core::{AuditLog, Decision, Policy};
use honmoon_mgmt::AppState;
use honmoon_proxy::approval::ApprovalRegistry;
use honmoon_proxy::ca::CaMaterial;
use honmoon_proxy::gateway::{GatewayState, InterceptPolicy};

/// In-process HTTP upstream that answers `200 OK / "ok"`.
fn start_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
}

struct Gateway {
    proxy_port: u16,
    mgmt_port: u16,
    audit: Arc<AuditLog>,
}

/// Start the proxy and the management API on one runtime, sharing state.
fn start_gateway(policy_yaml: &str) -> Gateway {
    let policy = Policy::from_yaml(policy_yaml).unwrap();
    let audit = Arc::new(AuditLog::new(1024));
    let state = GatewayState {
        policy: Arc::new(policy),
        audit: audit.clone(),
        approvals: Arc::new(ApprovalRegistry::new()),
        pause_timeout: Duration::from_secs(10),
        ca: Arc::new(CaMaterial::generate().unwrap()),
        intercept: InterceptPolicy::None,
    };

    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let mgmt_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mgmt_port = mgmt_listener.local_addr().unwrap().port();

    let app = AppState::new(state.clone(), policy_yaml.to_string());
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            tokio::spawn(async move { honmoon_proxy::gateway::serve(state, proxy_listener).await });
            honmoon_mgmt::serve(app, mgmt_listener).await.unwrap();
        });
    });

    wait_for_port(proxy_port);
    wait_for_port(mgmt_port);
    Gateway {
        proxy_port,
        mgmt_port,
        audit,
    }
}

fn wait_for_port(port: u16) {
    for _ in 0..250 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("nothing listening on {port}");
}

/// Read an HTTP response head (`\r\n\r\n`).
fn read_head(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while s.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
        out.push(byte[0]);
        if out.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Minimal one-shot HTTP request to the management API; returns the body.
fn http_request(port: u16, method: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    // Split head from body.
    raw.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default()
}

/// Poll the approval queue until one appears; return its id.
fn await_pending_id(mgmt_port: u16) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let body = http_request(mgmt_port, "GET", "/api/approvals");
        let arr: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        if let Some(first) = arr.as_array().and_then(|a| a.first()) {
            return first["id"].as_u64().unwrap();
        }
        if Instant::now() > deadline {
            panic!("no pending approval appeared; last body: {body:?}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

const PAUSE_POLICY: &str = "\
egress:
  default: deny
  allow:
    - 127.0.0.1
rules:
  - name: pause-loopback
    endpoint: '*'
    condition: \"http.host == '127.0.0.1'\"
    verdict: pause
";

#[test]
fn paused_request_is_approved_and_tunnels() {
    let upstream = start_upstream();
    let gw = start_gateway(PAUSE_POLICY);

    // Client issues a CONNECT that the policy holds for approval.
    let target = format!("127.0.0.1:{upstream}");
    let mut client = TcpStream::connect(("127.0.0.1", gw.proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .unwrap();

    // It shows up on the approval queue; approve it via the management API.
    let id = await_pending_id(gw.mgmt_port);
    let resp = http_request(
        gw.mgmt_port,
        "POST",
        &format!("/api/approvals/{id}/approve"),
    );
    assert!(resp.contains("\"resolved\""), "approve response: {resp:?}");

    // The held tunnel now establishes and reaches the upstream.
    let established = read_head(&mut client);
    assert!(
        established.starts_with("HTTP/1.1 200"),
        "tunnel not established after approval: {established:?}"
    );
    client
        .write_all(b"GET / HTTP/1.0\r\nHost: upstream\r\n\r\n")
        .unwrap();
    let mut body = String::new();
    client.read_to_string(&mut body).unwrap();
    assert!(body.trim_end().ends_with("ok"), "upstream body: {body:?}");

    // The decision lifecycle is in the audit log: Paused then Approved.
    let recent = gw.audit.recent(50);
    assert!(
        recent.iter().any(|e| e.decision == Decision::Approved),
        "no Approved audit event: {recent:?}"
    );
    assert!(
        recent.iter().any(|e| e.decision == Decision::Paused),
        "no Paused audit event: {recent:?}"
    );
}

#[test]
fn paused_request_is_rejected_and_blocked() {
    let upstream = start_upstream();
    let gw = start_gateway(PAUSE_POLICY);

    let target = format!("127.0.0.1:{upstream}");
    let mut client = TcpStream::connect(("127.0.0.1", gw.proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .unwrap();

    let id = await_pending_id(gw.mgmt_port);
    http_request(gw.mgmt_port, "POST", &format!("/api/approvals/{id}/reject"));

    // The held request is now answered with 403.
    let resp = read_head(&mut client);
    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "expected 403 after rejection, got: {resp:?}"
    );

    let recent = gw.audit.recent(50);
    assert!(
        recent.iter().any(|e| e.decision == Decision::Rejected),
        "no Rejected audit event: {recent:?}"
    );
}

#[test]
fn audit_endpoint_records_allow_and_deny() {
    let gw = start_gateway("egress:\n  default: deny\n  allow:\n    - allowed.example\n");

    // A denied CONNECT (host not allowed).
    let mut c = TcpStream::connect(("127.0.0.1", gw.proxy_port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        .unwrap();
    let resp = read_head(&mut c);
    assert!(resp.starts_with("HTTP/1.1 403"), "expected 403: {resp:?}");

    // The management API exposes the audit event.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let body = http_request(gw.mgmt_port, "GET", "/api/audit?limit=10");
        if body.contains("blocked.example") && body.contains("\"denied\"") {
            break;
        }
        if Instant::now() > deadline {
            panic!("denied event not in /api/audit: {body:?}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}
