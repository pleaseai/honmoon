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

use honmoon_core::{AuditLog, Decision, PathResolution, Policy};
use honmoon_mgmt::{AppState, HookSalt};
use honmoon_proxy::approval::ApprovalRegistry;
use honmoon_proxy::ca::CaMaterial;
use honmoon_proxy::gateway::{GatewayState, InterceptPolicy, PiiMode, RedactionState};

/// The management token every gateway in this file is started with.
///
/// There is no token-less mode to test against: `AppState` requires one (#173),
/// so a harness that sent no credential would only ever exercise 401s.
const MGMT_TOKEN: &str = "e2e-mgmt-token";

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
    start_gateway_with_hook(
        policy_yaml,
        HookSalt::fixed(b"e2e-hook-salt".to_vec()),
        MGMT_TOKEN.to_string(),
    )
}

fn start_gateway_with_hook(policy_yaml: &str, hook_salt: HookSalt, mgmt_token: String) -> Gateway {
    let policy = Policy::from_yaml(policy_yaml).unwrap();
    let audit = Arc::new(AuditLog::new(1024));
    let state = GatewayState {
        policy: Arc::new(policy),
        audit: audit.clone(),
        approvals: Arc::new(ApprovalRegistry::new()),
        pause_timeout: Duration::from_secs(10),
        ca: Arc::new(CaMaterial::generate().unwrap()),
        intercept: InterceptPolicy::None,
        pii_mode: PiiMode::Detect,
        redaction: None,
    };

    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let mgmt_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mgmt_port = mgmt_listener.local_addr().unwrap().port();

    let app = AppState::with_hook_config(
        state.clone(),
        policy_yaml.to_string(),
        hook_salt,
        mgmt_token,
    );
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
    let raw = http_request_with_body(port, method, path, &[], "");
    http_body(&raw).to_string()
}

/// Like [`http_request_with_body`], but sends exactly the headers given — no
/// credential is added. This is what the #173 tests use to stand in for a caller
/// who has no token.
fn http_request_raw(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> String {
    send(port, method, path, headers, body)
}

/// Every `/api/*` route requires the management token (#173), so this helper
/// supplies it and the ordinary behavioural tests read as they did before the
/// gate. A caller passing its own `Authorization` header keeps that one.
///
/// The credential tests do not use this helper at all: injecting a bearer is
/// exactly what they must not do, so they call [`http_request_raw`], which
/// sends only the headers it is given.
fn http_request_with_body(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> String {
    let authorization = format!("Bearer {MGMT_TOKEN}");
    let mut all = headers.to_vec();
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
    {
        all.push(("Authorization", authorization.as_str()));
    }
    send(port, method, path, &all, body)
}

fn send(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let extra_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    raw
}

fn http_body(raw: &str) -> &str {
    raw.split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default()
}

fn decode_chunked_body(raw: &[u8]) -> Vec<u8> {
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers")
        + 4;
    let mut rest = &raw[header_end..];
    let mut decoded = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size");
        let size = usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap(), 16)
            .expect("hex chunk size");
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    decoded
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
fn claude_code_hook_endpoint_redacts_and_requires_configured_bearer() {
    let salt = b"http-hook-parity-salt".to_vec();
    let gw = start_gateway_with_hook(
        "egress:\n  default: deny\n",
        HookSalt::fixed(salt.clone()),
        MGMT_TOKEN.to_string(),
    );
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": "key sk-ant-api03-http-parity-abcDEF123456"
    });
    let body = serde_json::to_string(&payload).unwrap();

    let unauthorized = http_request_raw(gw.mgmt_port, "POST", "/api/hooks/claude-code", &[], &body);
    assert!(
        unauthorized.starts_with("HTTP/1.1 401"),
        "missing bearer must be rejected: {unauthorized:?}"
    );

    let wrong = http_request_raw(
        gw.mgmt_port,
        "POST",
        "/api/hooks/claude-code",
        &[("Authorization", "Bearer not-the-token")],
        &body,
    );
    assert!(
        wrong.starts_with("HTTP/1.1 401"),
        "a wrong bearer must be rejected: {wrong:?}"
    );

    let authorized =
        http_request_with_body(gw.mgmt_port, "POST", "/api/hooks/claude-code", &[], &body);
    assert!(authorized.starts_with("HTTP/1.1 200"));
    let actual: serde_json::Value = serde_json::from_str(http_body(&authorized)).unwrap();
    let expected =
        honmoon_core::claude_code_hook_verdict(&payload, &salt, PathResolution::NotSensitive)
            .into_parts()
            .0;
    assert_eq!(actual, expected, "HTTP transport uses shared core verdict");
    assert!(!actual.to_string().contains("sk-ant-api03-http-parity"));
}

#[test]
fn claude_code_hook_resolves_agent_relative_paths_and_denies_unresolved() {
    let gw = start_gateway_with_hook(
        "egress:\n  default: deny\n",
        HookSalt::fixed(b"cwd-salt".to_vec()),
        MGMT_TOKEN.to_string(),
    );

    // Agent-side working directory holding an innocuously-named symlink to key
    // material — the issue #55 bypass scenario. The gateway runs in a different
    // cwd, so only the payload's `cwd` can anchor the relative path.
    let agent_dir = std::env::temp_dir().join(format!("honmoon-e2e-cwd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&agent_dir);
    std::fs::create_dir_all(&agent_dir).unwrap();
    std::fs::write(agent_dir.join("server.pem"), b"key material").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(agent_dir.join("server.pem"), agent_dir.join("config")).unwrap();
    #[cfg(not(unix))]
    std::fs::write(agent_dir.join("config"), b"stand-in").unwrap();

    let post = |payload: &serde_json::Value| -> serde_json::Value {
        let raw = http_request_with_body(
            gw.mgmt_port,
            "POST",
            "/api/hooks/claude-code",
            &[],
            &serde_json::to_string(payload).unwrap(),
        );
        assert!(raw.starts_with("HTTP/1.1 200"), "unexpected: {raw:?}");
        serde_json::from_str(http_body(&raw)).unwrap()
    };

    // With the agent's cwd in the payload the symlink resolves and is denied.
    #[cfg(unix)]
    {
        let verdict = post(&serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "cwd": agent_dir.to_string_lossy(),
            "tool_input": { "file_path": "config" }
        }));
        assert_eq!(
            verdict["hookSpecificOutput"]["permissionDecision"], "deny",
            "agent-relative symlink to key material must be denied: {verdict}"
        );
    }

    // Without a cwd the gateway cannot resolve the relative path at all; it
    // must deny conservatively (surfacing why) rather than silently pass.
    let verdict = post(&serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "config" }
    }));
    assert_eq!(verdict["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        verdict["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("could not be resolved"),
        "reason must surface the failed resolution: {verdict}"
    );

    // An absolute path to a not-yet-created file stays allowed (new-file case).
    let verdict = post(&serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "cwd": agent_dir.to_string_lossy(),
        "tool_input": { "file_path": agent_dir.join("new-file.rs").to_string_lossy() }
    }));
    assert_eq!(
        verdict,
        serde_json::json!({}),
        "new file must pass: {verdict}"
    );

    let _ = std::fs::remove_dir_all(&agent_dir);
}

#[test]
fn claude_code_hook_endpoint_accumulates_live_mappings() {
    let policy_yaml = "egress:\n  default: deny\n";
    let policy = Policy::from_yaml(policy_yaml).unwrap();
    let state = GatewayState::new(policy);
    let app = AppState::with_hook_config(
        state,
        policy_yaml,
        HookSalt::fixed(b"mapping-store-salt".to_vec()),
        MGMT_TOKEN.to_string(),
    );
    let mappings = app.hook_mappings.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(honmoon_mgmt::serve(app, listener)).unwrap();
    });
    wait_for_port(port);

    for secret in [
        "sk-ant-api03-live-mapping-one-abcDEF123456",
        "sk-ant-api03-live-mapping-two-abcDEF123456",
    ] {
        let payload = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": format!("key {secret}")
        });
        let raw = http_request_with_body(
            port,
            "POST",
            "/api/hooks/claude-code",
            &[],
            &serde_json::to_string(&payload).unwrap(),
        );
        assert!(raw.starts_with("HTTP/1.1 200"));
    }
    assert_eq!(mappings.len(), 2, "both reversible mappings stay live");
}

/// What one secret's trip through the hook endpoint and back over the wire
/// produced.
struct WireRoundTrip {
    /// The placeholder the hook endpoint minted.
    hook_token: String,
    /// The request body the upstream actually received.
    captured_request: String,
    /// The response body the client got back, after the proxy's restore pass.
    restored_response: String,
    /// Live mappings in the store the proxy detokenizes from.
    mappings: usize,
}

/// Redact `payload` at the hook endpoint, then have an upstream echo the minted
/// placeholder back through the proxy, and report what came out.
///
/// Shared by the fixed-salt and per-session cases. Restoring is a mapping-store
/// lookup, so it must not care which salt minted the token — but "must not care"
/// is the claim, and each variant needs its own proof rather than inheriting the
/// other's. Both callers drive the same real proxy, real management API, and real
/// upstream over loopback.
fn hook_then_wire_round_trip(
    hook_salt: HookSalt,
    wire_salt: Vec<u8>,
    payload: serde_json::Value,
) -> WireRoundTrip {
    let policy_yaml = "egress:\n  default: allow\n";
    let mut state = GatewayState::new(Policy::from_yaml(policy_yaml).unwrap());
    state.redaction = Some(RedactionState::new(wire_salt));
    let proxy_mappings = Arc::clone(&state.redaction.as_ref().unwrap().mappings);
    let app = AppState::with_hook_config(
        state.clone(),
        policy_yaml,
        hook_salt,
        MGMT_TOKEN.to_string(),
    );
    assert!(
        Arc::ptr_eq(&app.hook_mappings, &proxy_mappings),
        "the hook endpoint writes into the proxy's own store"
    );

    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let mgmt_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mgmt_port = mgmt_listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            tokio::spawn(async move { honmoon_proxy::gateway::serve(state, proxy_listener).await });
            honmoon_mgmt::serve(app, mgmt_listener).await.unwrap();
        });
    });
    wait_for_port(proxy_port);
    wait_for_port(mgmt_port);

    let hook_response = http_request_with_body(
        mgmt_port,
        "POST",
        "/api/hooks/claude-code",
        &[],
        &serde_json::to_string(&payload).unwrap(),
    );
    let hook_json: serde_json::Value = serde_json::from_str(http_body(&hook_response)).unwrap();
    let hook_output = hook_json["hookSpecificOutput"]["updatedToolOutput"]
        .as_str()
        .expect("the hook redacted the tool output");
    let token_start = hook_output
        .find("<<hs:")
        .expect("the hook minted a placeholder");
    let token_end = hook_output[token_start..].find(">>").unwrap() + token_start + 2;
    let hook_token = hook_output[token_start..token_end].to_string();

    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let (capture_tx, capture_rx) = std::sync::mpsc::channel();
    let response_token = hook_token.clone();
    thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 2048];
        let header_end = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(position) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        while bytes.len() < header_end + content_length {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&buffer[..read]);
        }
        capture_tx
            .send(bytes[header_end..header_end + content_length].to_vec())
            .unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_token}",
            response_token.len()
        )
        .unwrap();
    });

    let wire_body = "proxy request contains no redactable value";
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        client,
        "POST http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{wire_body}",
        wire_body.len()
    )
    .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let captured_request =
        String::from_utf8(capture_rx.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    assert_eq!(
        captured_request, wire_body,
        "the request leg had nothing to redact"
    );
    WireRoundTrip {
        hook_token,
        captured_request,
        restored_response: String::from_utf8(decode_chunked_body(&response)).unwrap(),
        mappings: proxy_mappings.len(),
    }
}

/// The realistic `--redact-secrets` deployment with no pinned context: wire
/// redaction is on (process-scoped salt) while the hook endpoint keys on the
/// session. `with_hook_config` no longer asserts the two salts match in that
/// combination (#98), so prove the combination actually works end to end —
/// a session-salted placeholder minted by the hook is still restored by the
/// proxy, which is the property the dropped assert used to stand in for.
#[test]
fn a_per_session_hook_placeholder_is_restored_by_wire_redaction() {
    const SECRET: &str = "sk-ant-api03-per-session-with-wire-abcDEF123456";
    let trip = hook_then_wire_round_trip(
        HookSalt::per_session(b"machine-key-for-per-session".to_vec()),
        b"process-scoped-wire-salt".to_vec(),
        serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "session_id": "session-with-wire-redaction",
            "tool_response": format!("key {SECRET}")
        }),
    );

    assert!(!trip.captured_request.contains(SECRET));
    assert_eq!(
        trip.mappings, 1,
        "the session-salted mapping is recorded in the proxy's store"
    );
    assert_eq!(
        trip.restored_response, SECRET,
        "the proxy restores a placeholder its own salt never minted"
    );
    assert!(!trip.restored_response.contains(&trip.hook_token));
}

#[test]
fn hook_created_mapping_restores_proxy_response_without_request_remint() {
    const SECRET: &str = "sk-ant-api03-hook-wire-parity-abcDEF123456";
    let salt = b"hook-wire-shared-salt".to_vec();
    let trip = hook_then_wire_round_trip(
        HookSalt::fixed(salt.clone()),
        salt,
        serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": format!("hook sees {SECRET}")
        }),
    );

    assert!(!trip.captured_request.contains(SECRET));
    assert!(!trip.captured_request.contains("<<hs:"));
    assert_eq!(trip.mappings, 1, "only the hook-created mapping exists");
    assert_eq!(trip.restored_response, SECRET);
    assert!(!trip.restored_response.contains(&trip.hook_token));
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

// ---------------------------------------------------------------------------
// #173 — the management read surface is behind the management token.
// ---------------------------------------------------------------------------

/// A policy whose paused host is a distinctive marker, so one gateway seeds all
/// three read routes with a string that must not escape without a credential:
/// `/api/policy` serves the policy source, a held CONNECT to the marker host
/// puts it on `/api/approvals`, and the `pause` verdict records it in
/// `/api/audit`.
const MARKER_HOST: &str = "127.0.0.1";
const MARKER_RULE: &str = "held-marker-rule";

const MARKER_POLICY: &str = "\
egress:
  default: deny
  allow:
    - 127.0.0.1
rules:
  - name: held-marker-rule
    endpoint: '*'
    condition: \"http.host == '127.0.0.1'\"
    verdict: pause
";

/// Start a gateway on [`MARKER_POLICY`] and hold one CONNECT on its approval
/// queue, so every read route has something worth stealing. Returns the gateway
/// and the held client (kept alive: dropping it resolves the approval).
fn gateway_with_a_held_request() -> (Gateway, TcpStream) {
    let upstream = start_upstream();
    let gw = start_gateway(MARKER_POLICY);
    let target = format!("{MARKER_HOST}:{upstream}");
    let mut client = TcpStream::connect(("127.0.0.1", gw.proxy_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .unwrap();
    await_pending_id(gw.mgmt_port);
    (gw, client)
}

const READ_ROUTES: [&str; 3] = ["/api/audit?limit=50", "/api/approvals", "/api/policy"];

/// The defect in #173: the three reads answered anyone who could reach the
/// listener. The assertion is about the *data*, not the status line — a gate
/// that returned 401 while still writing the body would pass a status-only
/// check.
#[test]
fn read_routes_serve_no_data_without_a_credential() {
    let (gw, _held) = gateway_with_a_held_request();

    for route in READ_ROUTES {
        let raw = http_request_raw(gw.mgmt_port, "GET", route, &[], "");
        assert!(
            raw.starts_with("HTTP/1.1 401"),
            "{route} answered without a credential: {raw:?}"
        );
        assert!(
            !raw.contains(MARKER_RULE),
            "{route} leaked policy/approval data to an unauthenticated caller: {raw:?}"
        );
    }

    // A wrong token is no better than none.
    for route in READ_ROUTES {
        let raw = http_request_raw(
            gw.mgmt_port,
            "GET",
            route,
            &[("Authorization", "Bearer not-the-token")],
            "",
        );
        assert!(
            raw.starts_with("HTTP/1.1 401"),
            "{route} accepted a wrong token: {raw:?}"
        );
        assert!(
            !raw.contains(MARKER_RULE),
            "{route} leaked on a wrong token"
        );
    }
}

/// The other half of the gate: with the token the three reads still work. A
/// change that simply broke them would pass the test above on its own.
#[test]
fn read_routes_answer_with_the_management_token() {
    let (gw, _held) = gateway_with_a_held_request();

    for route in READ_ROUTES {
        let raw = http_request_with_body(gw.mgmt_port, "GET", route, &[], "");
        assert!(
            raw.starts_with("HTTP/1.1 200"),
            "{route} rejected the management token: {raw:?}"
        );
    }
    assert!(
        http_request(gw.mgmt_port, "GET", "/api/policy").contains(MARKER_RULE),
        "the policy read must still serve the policy"
    );
    assert!(
        http_request(gw.mgmt_port, "GET", "/api/approvals").contains("\"id\""),
        "the approval queue must still serve the held request"
    );
}

/// Resolving a held request is a write, and it was open too: an unauthenticated
/// caller could approve its own paused egress. Assert the approval is still
/// pending afterwards, not merely that the call was refused.
#[test]
fn approval_writes_require_a_credential() {
    let (gw, _held) = gateway_with_a_held_request();
    let id = await_pending_id(gw.mgmt_port);

    for action in ["approve", "reject"] {
        let raw = http_request_raw(
            gw.mgmt_port,
            "POST",
            &format!("/api/approvals/{id}/{action}"),
            &[],
            "",
        );
        assert!(
            raw.starts_with("HTTP/1.1 401"),
            "{action} without a credential: {raw:?}"
        );
    }

    assert_eq!(
        await_pending_id(gw.mgmt_port),
        id,
        "the held request must still be pending after the refused writes"
    );
}

/// `/healthz` and the dashboard shell stay open — the first carries no data, the
/// second is the binary's own bundled code. Stated as a test so a future
/// blanket gate does not log the dashboard out before it can log in.
#[test]
fn healthz_and_the_dashboard_shell_stay_open() {
    let (gw, _held) = gateway_with_a_held_request();

    let health = http_request_raw(gw.mgmt_port, "GET", "/healthz", &[], "");
    assert!(health.starts_with("HTTP/1.1 200"), "healthz: {health:?}");

    let shell = http_request_raw(gw.mgmt_port, "GET", "/", &[], "");
    assert!(
        shell.starts_with("HTTP/1.1 200"),
        "dashboard shell: {shell:?}"
    );
    assert!(
        shell.contains("<html") || shell.contains("<!doctype"),
        "dashboard shell is not HTML: {shell:?}"
    );
    assert!(
        !shell.contains(MGMT_TOKEN),
        "the shell must not carry the token — anyone who can reach the listener can read it"
    );
}

/// The `Set-Cookie` value from a response head, if any.
///
/// Kept after the session cookie was removed (#188) precisely so the tests can
/// assert its *absence*: the property that closes the sibling-port harvest is
/// that this listener sets no cookie at all, and only a helper that can still
/// find one can prove there is none.
fn set_cookie(raw: &str) -> Option<String> {
    raw.lines()
        .find_map(|line| line.strip_prefix("set-cookie: "))
        .or_else(|| {
            raw.lines()
                .find_map(|line| line.strip_prefix("Set-Cookie: "))
        })
        .map(|value| value.trim().to_string())
}

/// The `Location` value from a response head, if any.
fn location(raw: &str) -> Option<String> {
    raw.lines()
        .find_map(|line| line.strip_prefix("location: "))
        .or_else(|| raw.lines().find_map(|line| line.strip_prefix("Location: ")))
        .map(|value| value.trim().to_string())
}

/// The header name the dashboard sends its session secret in (#188).
///
/// Spelled out rather than imported so this file pins the *wire* name a browser
/// build would have to keep, not whatever the constant happens to say.
const SESSION_HEADER: &str = "X-Honmoon-Session";

/// The session secret out of a successful `/login`'s redirect target.
///
/// The secret rides in the URL fragment, which a browser never sends to any
/// server — the dashboard's own script reads it out of `location.hash` and
/// keeps it in origin-scoped `sessionStorage`.
fn session_secret(login: &str) -> String {
    let target = location(login).expect("login must redirect");
    let (path, fragment) = target
        .split_once('#')
        .unwrap_or_else(|| panic!("login redirect carries no fragment: {target:?}"));
    assert_eq!(path, "/", "login must land on the dashboard root");
    fragment
        .strip_prefix("session=")
        .unwrap_or_else(|| panic!("unexpected fragment shape: {fragment:?}"))
        .to_string()
}

/// The dashboard's own load path, end to end: fetch the shell with no
/// credential, exchange the token at `/login` for the session secret the
/// redirect's fragment carries, then make the three calls
/// `apps/dashboard/src/api.ts` makes — with only the header its script attaches.
/// A gate that locked the dashboard out would fail here.
#[test]
fn the_dashboard_load_path_reads_every_route_with_its_session_header() {
    let (gw, _held) = gateway_with_a_held_request();

    // 1. The browser loads the shell. No credential yet, and none is leaked.
    let shell = http_request_raw(gw.mgmt_port, "GET", "/", &[], "");
    assert!(shell.starts_with("HTTP/1.1 200"), "shell: {shell:?}");

    // 2. The operator opens the login URL honmoon printed at startup. It hands
    //    back a session secret in the redirect fragment and — the property this
    //    issue is about — sets no cookie: a cookie's scope carries no port
    //    (RFC 6265 §8.5), so anything set here would be sent to every other
    //    listener on `127.0.0.1` as well.
    let login = http_request_raw(
        gw.mgmt_port,
        "GET",
        &format!("/login?token={MGMT_TOKEN}"),
        &[],
        "",
    );
    assert!(login.starts_with("HTTP/1.1 303"), "login: {login:?}");
    assert!(
        set_cookie(&login).is_none(),
        "login must set no cookie — a sibling loopback port receives every one: {login:?}"
    );
    let secret = session_secret(&login);
    assert!(
        !secret.is_empty() && secret != MGMT_TOKEN,
        "the session secret must not be the token itself: {secret:?}"
    );

    // 3. The three reads `api.ts` makes, with only what its script attaches.
    for route in READ_ROUTES {
        let raw = http_request_raw(gw.mgmt_port, "GET", route, &[(SESSION_HEADER, &secret)], "");
        assert!(
            raw.starts_with("HTTP/1.1 200"),
            "{route} refused the dashboard's session header: {raw:?}"
        );
    }
    assert!(
        http_request_raw(
            gw.mgmt_port,
            "GET",
            "/api/policy",
            &[(SESSION_HEADER, &secret)],
            ""
        )
        .contains(MARKER_RULE),
        "the dashboard must see real policy data through its session header"
    );

    // 4. A wrong token mints nothing — no secret, and no cookie either.
    let refused = http_request_raw(gw.mgmt_port, "GET", "/login?token=wrong", &[], "");
    assert!(refused.starts_with("HTTP/1.1 401"), "login: {refused:?}");
    assert!(
        set_cookie(&refused).is_none(),
        "a refused login must not set a cookie"
    );
    assert!(
        location(&refused).is_none(),
        "a refused login must not hand out a redirect target: {refused:?}"
    );
}

/// The dashboard's write travels on the same header, with no browser labelling
/// of any kind.
///
/// A cookie is attached by the browser, so a cookie-authenticated write had to
/// be checked against `Sec-Fetch-Site`/`Origin` to tell the dashboard's own
/// request from one a sibling-port page provoked. A header the page must set
/// itself is not ambient authority: no page can cause a browser to attach it
/// (a custom header forces a CORS preflight this service never answers), so
/// there is nothing for an origin check to distinguish and the write needs no
/// browser evidence — the same reasoning the bearer has always had.
#[test]
fn a_session_header_write_needs_no_browser_labelling() {
    let (gw, _held) = gateway_with_a_held_request();
    let id = await_pending_id(gw.mgmt_port);
    let login = http_request_raw(
        gw.mgmt_port,
        "GET",
        &format!("/login?token={MGMT_TOKEN}"),
        &[],
        "",
    );
    let secret = session_secret(&login);

    let approved = http_request_raw(
        gw.mgmt_port,
        "POST",
        &format!("/api/approvals/{id}/approve"),
        &[(SESSION_HEADER, &secret)],
        "",
    );
    assert!(
        approved.starts_with("HTTP/1.1 200"),
        "the dashboard's own write must work: {approved:?}"
    );
}

/// No cookie is a credential, so a sibling loopback port has nothing to harvest.
///
/// This is the defect from issue #188, asserted as an absence rather than as a
/// status code. Cookie scope has no port (RFC 6265 §8.5), so a listener another
/// local user stands up on `127.0.0.1:9999` receives `honmoon_session` from any
/// request a page can provoke (`<img src="http://127.0.0.1:9999/x">`) and then
/// replays it off-browser, where `Sec-Fetch-Site` and `Origin` are ordinary
/// headers it sets itself. No header check can tell that replay from the
/// dashboard, which is why the fix is that there is no cookie: `/login` sets
/// none (asserted above) and this route accepts none — including the genuine
/// session secret presented where the old cookie went, which is exactly what a
/// harvester would hold.
#[test]
fn no_session_cookie_is_a_credential_so_a_sibling_port_has_nothing_to_harvest() {
    let (gw, _held) = gateway_with_a_held_request();
    let id = await_pending_id(gw.mgmt_port);
    let login = http_request_raw(
        gw.mgmt_port,
        "GET",
        &format!("/login?token={MGMT_TOKEN}"),
        &[],
        "",
    );
    let secret = session_secret(&login);
    let approve = format!("/api/approvals/{id}/approve");

    for value in [
        // The real secret, in the cookie a harvester would have collected.
        format!("honmoon_session={secret}"),
        "honmoon_session=garbage".to_string(),
        // The secret is an HMAC *of* the token, so the token itself is not it.
        format!("honmoon_session={MGMT_TOKEN}"),
        // A real-looking name that is not ours, alongside nothing else.
        format!("other_session={secret}"),
    ] {
        for route in READ_ROUTES {
            let raw = http_request_raw(gw.mgmt_port, "GET", route, &[("Cookie", &value)], "");
            assert!(
                raw.starts_with("HTTP/1.1 401"),
                "{route} accepted a cookie {value:?}: {raw:?}"
            );
            assert!(
                !raw.contains(MARKER_RULE),
                "{route} leaked data to a cookie {value:?}: {raw:?}"
            );
        }
        // Labelled as the browser would label the dashboard's own request, so a
        // surviving origin check could not be what refuses this.
        let write = http_request_raw(
            gw.mgmt_port,
            "POST",
            &approve,
            &[("Cookie", &value), ("Sec-Fetch-Site", "same-origin")],
            "",
        );
        assert!(
            write.starts_with("HTTP/1.1 401"),
            "the approval write accepted a cookie {value:?}: {write:?}"
        );
        assert_eq!(
            await_pending_id(gw.mgmt_port),
            id,
            "a cookie write must not have resolved the approval ({value:?})"
        );
    }

    // The legitimate off-browser caller holds the token and sends the bearer,
    // which the refusals above must not have cost anything.
    let with_bearer = http_request_raw(
        gw.mgmt_port,
        "POST",
        &approve,
        &[("Authorization", &format!("Bearer {MGMT_TOKEN}"))],
        "",
    );
    assert!(
        with_bearer.starts_with("HTTP/1.1 200"),
        "a bearer write must still work: {with_bearer:?}"
    );
}

/// A session secret that is not the minted one buys nothing, and neither does
/// the token itself presented where the secret belongs.
#[test]
fn a_forged_session_header_reads_no_data() {
    let (gw, _held) = gateway_with_a_held_request();
    for value in [
        "garbage",
        // The secret is an HMAC *of* the token, so the token itself is not it.
        MGMT_TOKEN, "",
    ] {
        for route in READ_ROUTES {
            let raw = http_request_raw(gw.mgmt_port, "GET", route, &[(SESSION_HEADER, value)], "");
            assert!(
                raw.starts_with("HTTP/1.1 401"),
                "{route} accepted a forged session header {value:?}: {raw:?}"
            );
            assert!(
                !raw.contains(MARKER_RULE),
                "{route} leaked data to a forged session header {value:?}: {raw:?}"
            );
        }
    }
}
