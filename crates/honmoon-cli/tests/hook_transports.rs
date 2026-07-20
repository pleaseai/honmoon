//! Cross-process and cross-transport regression tests for Claude Code hooks.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use honmoon_core::{AuditLog, Policy};
use honmoon_mgmt::AppState;
use honmoon_proxy::approval::ApprovalRegistry;
use honmoon_proxy::ca::CaMaterial;
use honmoon_proxy::gateway::{GatewayState, InterceptPolicy, PiiMode};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const CONTEXT: &str = "shared-test-session";
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
    serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": format!("credential {SECRET}")
    })
    .to_string()
}

fn invoke_cli(home: &Path, input: &str) -> Vec<u8> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_honmoon"))
        .args(["hook", "--salt-context", CONTEXT])
        .env("HOME", home)
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

fn start_mgmt(salt: Vec<u8>) -> u16 {
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
    let app = AppState::with_hook_config(state, policy_yaml, salt, None);
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
        "POST /api/hooks/claude-code HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    let first = invoke_cli(home.path(), &input);
    let second = invoke_cli(home.path(), &input);
    assert_eq!(first, second);
    assert!(!String::from_utf8_lossy(&first).contains(SECRET));
}

#[test]
fn cli_and_management_endpoint_are_byte_identical_for_same_salt_context() {
    let home = TempHome::new();
    let input = payload();
    let cli = invoke_cli(home.path(), &input);
    let http = invoke_http(start_mgmt(derived_salt()), &input);
    assert_eq!(cli, http);
}
