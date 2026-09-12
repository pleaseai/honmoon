//! Cross-process and cross-transport regression tests for Claude Code hooks.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use honmoon_core::{AuditLog, PLACEHOLDER_PREFIX, PLACEHOLDER_SUFFIX, Policy};
use honmoon_mgmt::{AppState, HookSalt};
use honmoon_proxy::approval::ApprovalRegistry;
use honmoon_proxy::ca::CaMaterial;
use honmoon_proxy::gateway::{GatewayState, InterceptPolicy, PiiMode};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const CONTEXT: &str = "shared-test-session";
/// Every `/api/*` route requires the management token (#173), the HTTP hook
/// transport included.
const MGMT_TOKEN: &str = "hook-transport-mgmt-token";
const MACHINE_SALT: &[u8] = b"0123456789abcdef0123456789abcdef";
const SECRET: &str = "sk-ant-api03-cross-process-abcDEF123456";

struct TempHome(PathBuf);

impl TempHome {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "honmoon-hook-integration-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join(".honmoon")).unwrap();
        std::fs::write(path.join(".honmoon/hook-salt"), MACHINE_SALT).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn payload() -> String {
    hook_event(None)
}

/// The same event, tagged with the session the agent is in — what the plugin
/// sends on every hook over either transport.
fn session_payload(session_id: &str) -> String {
    hook_event(Some(session_id))
}

fn hook_event(session_id: Option<&str>) -> String {
    let mut event = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": format!("credential {SECRET}")
    });
    if let Some(session_id) = session_id {
        event["session_id"] = serde_json::json!(session_id);
    }
    event.to_string()
}

/// The placeholder a verdict minted. Panics when there is none, so a parity
/// assertion can never pass by comparing two verdicts that redacted nothing.
fn placeholder(verdict: &[u8]) -> String {
    let verdict = String::from_utf8(verdict.to_vec()).expect("verdict is UTF-8");
    let start = verdict
        .find(PLACEHOLDER_PREFIX)
        .unwrap_or_else(|| panic!("verdict mints no placeholder: {verdict}"));
    let end = verdict[start..]
        .find(PLACEHOLDER_SUFFIX)
        .unwrap_or_else(|| panic!("unterminated placeholder: {verdict}"));
    verdict[start..start + end + PLACEHOLDER_SUFFIX.len()].to_string()
}

fn invoke_cli(home: &Path, salt_context: Option<&str>, input: &str) -> Vec<u8> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_honmoon"));
    command.arg("hook");
    if let Some(salt_context) = salt_context {
        command.args(["--salt-context", salt_context]);
    }
    let mut child = command
        .env("HOME", home)
        // A pinned context outranks the payload's session, so an exported value
        // in the developer's (or CI's) environment would quietly decide what
        // these tests are measuring.
        .env_remove("HONMOON_HOOK_SALT_CONTEXT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn derived_salt() -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(MACHINE_SALT).unwrap();
    mac.update(CONTEXT.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn start_mgmt(salt: HookSalt) -> u16 {
    let policy_yaml = "egress:\n  default: deny\n";
    let state = GatewayState {
        policy: Arc::new(Policy::from_yaml(policy_yaml).unwrap()),
        audit: Arc::new(AuditLog::new(8)),
        approvals: Arc::new(ApprovalRegistry::new()),
        pause_timeout: Duration::from_secs(1),
        ca: Arc::new(CaMaterial::generate().unwrap()),
        intercept: InterceptPolicy::None,
        pii_mode: PiiMode::Detect,
        redaction: None,
    };
    let app = AppState::with_hook_config(state, policy_yaml, salt, MGMT_TOKEN.to_string());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime
            .block_on(honmoon_mgmt::serve(app, listener))
            .unwrap();
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return port;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("management API did not start");
}

fn invoke_http(port: u16, body: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "POST /api/hooks/claude-code HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {MGMT_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let boundary = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    response[boundary..].to_vec()
}

#[test]
fn separate_cli_invocations_with_same_context_are_byte_identical() {
    let home = TempHome::new();
    let input = payload();
    let first = invoke_cli(home.path(), Some(CONTEXT), &input);
    let second = invoke_cli(home.path(), Some(CONTEXT), &input);
    assert_eq!(first, second);
    assert!(!String::from_utf8_lossy(&first).contains(SECRET));
}

#[test]
fn cli_and_management_endpoint_are_byte_identical_for_same_salt_context() {
    let home = TempHome::new();
    let input = payload();
    let cli = invoke_cli(home.path(), Some(CONTEXT), &input);
    let http = invoke_http(start_mgmt(HookSalt::fixed(derived_salt())), &input);
    assert_eq!(cli, http);
}

/// Issue #98: with no context pinned on either side, both transports must key
/// the placeholder on the payload's own `session_id` — so a session that mixes
/// them (command hooks plus an http function-hook module) still shows the model
/// one token per secret, and one session's token never doubles as another's.
#[test]
fn cli_and_management_endpoint_mint_identical_per_session_placeholders() {
    let home = TempHome::new();
    let port = start_mgmt(HookSalt::per_session(MACHINE_SALT.to_vec()));
    let mut tokens = Vec::new();
    for session_id in ["session-98-a", "session-98-b"] {
        let input = session_payload(session_id);
        let cli = invoke_cli(home.path(), None, &input);
        let http = invoke_http(port, &input);
        assert_eq!(
            cli, http,
            "transports must mint the same placeholder for session {session_id}"
        );
        assert!(!String::from_utf8_lossy(&cli).contains(SECRET));
        tokens.push(placeholder(&cli));
    }
    assert_ne!(
        tokens[0], tokens[1],
        "distinct sessions must not share a placeholder for one secret"
    );
}
