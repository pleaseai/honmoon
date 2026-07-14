//! `honmoon hook` — the Claude Code plugin's command-transport backend (#19).
//!
//! Reads one hook-event JSON object on stdin, runs the `honmoon-core`
//! redaction engine, and writes the hook verdict JSON to stdout (or nothing
//! for a no-op). It **always exits 0**: a JSON verdict on stdout with exit 0 is
//! how a command hook applies a decision; exit 2 would instead be a *blocking
//! error* whose stdout JSON Claude Code ignores. Redaction failures (bad JSON,
//! unreadable salt dir) degrade to a no-op rather than a loud error, since the
//! proxy remains the enforcement backstop.
//!
//! Handlers by event:
//! - `PostToolUse` (matcher `Read`): redact the tool result via
//!   `hookSpecificOutput.updatedToolOutput` so the redacted form is what enters
//!   the model context (and, per issue #19, ideally the transcript).
//! - `UserPromptSubmit`: a hook cannot rewrite a prompt, so a prompt carrying a
//!   secret or high-severity identifier is `decision:"block"`ed with an
//!   actionable reason.
//! - `PreToolUse` (matcher `Read`): deny reads of known-sensitive paths before
//!   the file is opened (so plaintext never reaches the transcript at all).

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use honmoon_core::{DEFAULT_MIN_PII_SEVERITY, redact};
use serde_json::{Value, json};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// PII severity worth blocking a prompt over (HIGH: RRN, card, …). Mirrors the
/// `SEV_HIGH` scale in `honmoon_core::pii`; medium PII (email/phone) is common
/// in prompts and the proxy already scrubs the wire, so it does not block.
const PII_SEVERITY_HIGH: i64 = 3;

/// Entry point for `honmoon hook`: read stdin, dispatch, write stdout. Never
/// fails the process for expected error conditions (see module docs).
pub fn run() -> Result<()> {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return Ok(());
    }
    let payload: Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("honmoon hook: ignoring unparseable payload ({e})");
            return Ok(());
        }
    };

    let salt = session_salt(&payload);
    if let Some(verdict) = handle_hook(&payload, &salt) {
        let stdout = std::io::stdout();
        serde_json::to_writer(stdout.lock(), &verdict).context("writing hook verdict to stdout")?;
    }
    Ok(())
}

/// Dispatch a parsed hook payload to the matching handler, returning the JSON
/// verdict to print (or `None` for a no-op). Pure and salt-parameterized so it
/// is unit-testable without stdin or the filesystem.
pub fn handle_hook(payload: &Value, salt: &[u8]) -> Option<Value> {
    match payload.get("hook_event_name").and_then(Value::as_str)? {
        "PreToolUse" => handle_pre_tool_use(payload),
        "PostToolUse" => handle_post_tool_use(payload, salt),
        "UserPromptSubmit" => handle_user_prompt_submit(payload, salt),
        _ => None,
    }
}

/// Deny a `Read` of a known-sensitive path so its plaintext never enters the
/// transcript. Complements static permission rules like `Read(./.env)`.
fn handle_pre_tool_use(payload: &Value) -> Option<Value> {
    let file_path = payload
        .get("tool_input")
        .and_then(|i| i.get("file_path"))
        .and_then(Value::as_str)?;
    if !is_sensitive_path(file_path) {
        return None;
    }
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": format!(
                "honmoon: reading `{file_path}` is blocked — it matches a known-sensitive \
                 path (credentials or key material). If a specific value is genuinely \
                 needed, ask the user to provide just that value."
            )
        }
    }))
}

/// Replace the tool result with a redacted copy. The `tool_response` shape is
/// tool-specific and undocumented (a string for some tools, an object for
/// others), so every string leaf is redacted recursively.
fn handle_post_tool_use(payload: &Value, salt: &[u8]) -> Option<Value> {
    let response = payload.get("tool_response")?;
    let (redacted, changed) = redact_json_value(response, salt);
    if !changed {
        return None;
    }
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": redacted
        }
    }))
}

/// Block a prompt carrying a secret or high-severity identifier. A
/// `UserPromptSubmit` hook cannot rewrite the prompt, so blocking with an
/// actionable reason is the best available action.
fn handle_user_prompt_submit(payload: &Value, salt: &[u8]) -> Option<Value> {
    let prompt = payload.get("prompt").and_then(Value::as_str)?;
    let outcome = redact(prompt, salt, DEFAULT_MIN_PII_SEVERITY);
    if !(outcome.has_secret() || outcome.max_pii_severity >= PII_SEVERITY_HIGH) {
        return None;
    }
    let kinds = outcome.labels().join(", ");
    Some(json!({
        "decision": "block",
        "reason": format!(
            "honmoon: your prompt appears to contain a secret or sensitive identifier \
             ({kinds}). A prompt-submit hook cannot rewrite the prompt, so it was blocked. \
             Remove the value (or reference it indirectly) and resubmit."
        )
    }))
}

/// Recursively redact every string leaf of a JSON value, returning the redacted
/// value and whether anything changed.
fn redact_json_value(value: &Value, salt: &[u8]) -> (Value, bool) {
    match value {
        Value::String(s) => {
            let outcome = redact(s, salt, DEFAULT_MIN_PII_SEVERITY);
            (Value::String(outcome.text), outcome.redacted)
        }
        Value::Array(items) => {
            let mut changed = false;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let (redacted, item_changed) = redact_json_value(item, salt);
                changed |= item_changed;
                out.push(redacted);
            }
            (Value::Array(out), changed)
        }
        Value::Object(map) => {
            let mut changed = false;
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, val) in map {
                let (redacted, val_changed) = redact_json_value(val, salt);
                changed |= val_changed;
                out.insert(key.clone(), redacted);
            }
            (Value::Object(out), changed)
        }
        // Numbers / booleans / null cannot carry a secret surface.
        other => (other.clone(), false),
    }
}

/// Whether `path` names a credential/key file that should never be read into
/// the transcript. Case-insensitive; template files (`.env.example`, …) are
/// intentionally allowed since they hold no real secrets.
fn is_sensitive_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit(['/', '\\']).next().unwrap_or(lower.as_str());

    // Template / sample files are meant to be read and hold no real secrets.
    const TEMPLATE_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist"];
    if TEMPLATE_SUFFIXES.iter().any(|s| base.ends_with(s)) {
        return false;
    }

    // Dotenv, in any variant (`.env`, `.env.local`, `.env.production`).
    if base == ".env" || base.starts_with(".env.") {
        return true;
    }

    // Exact credential/key basenames (private SSH keys are extension-less).
    const SENSITIVE_BASENAMES: &[&str] = &[
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    ];
    if SENSITIVE_BASENAMES.contains(&base) {
        return true;
    }

    // Key-material extensions.
    const SENSITIVE_EXTENSIONS: &[&str] =
        &[".pem", ".key", ".p12", ".pfx", ".keystore", ".jks", ".asc"];
    if SENSITIVE_EXTENSIONS.iter().any(|e| base.ends_with(e)) {
        return true;
    }

    // Whole-path fragments for well-known secret locations. Deliberately narrow:
    // `.ssh/` is NOT blocked wholesale (it also holds public `.pub` keys,
    // `known_hosts`, `config`) — the extension-less private keys above cover the
    // secret case, and any PEM private-key *content* that is read anyway is still
    // caught by the PostToolUse `PRIVATE_KEY` detector.
    const SENSITIVE_FRAGMENTS: &[&str] = &["/.aws/credentials", "/.gnupg/"];
    SENSITIVE_FRAGMENTS.iter().any(|f| lower.contains(f))
}

/// Directory for honmoon's persisted local material (mirrors the CA dir in
/// `main.rs`): `$HOME/.honmoon`, else `.honmoon`.
fn honmoon_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".honmoon"),
        None => PathBuf::from(".honmoon"),
    }
}

/// Derive the per-session HMAC salt. Stable across every `hook` invocation in a
/// session (so a given secret tokenizes to the identical placeholder each turn
/// — issue #20), distinct per session, and unforgeable while the persisted
/// machine salt stays secret. Falls back to a fixed-key derivation if the salt
/// file can't be read/written, which keeps redaction working and deterministic
/// (only the unforgeability property is relaxed).
fn session_salt(payload: &Value) -> Vec<u8> {
    let session_id = payload
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let key = match load_or_create_machine_salt(&honmoon_dir()) {
        Ok(salt) => salt,
        Err(e) => {
            eprintln!("honmoon hook: using fallback salt ({e:#})");
            b"honmoon-hook-v1-fallback-key".to_vec()
        }
    };
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&key).expect("HMAC accepts a key of any length");
    mac.update(session_id.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Read (or generate on first use) the persisted 32-byte machine secret used as
/// the HMAC key behind placeholder unforgeability. Written `0600`.
fn load_or_create_machine_salt(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join("hook-salt");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() >= 16 {
            return Ok(bytes);
        }
    }
    let salt = random_bytes(32)?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::write(&path, &salt).with_context(|| format!("writing {}", path.display()))?;
    set_permissions_0600(&path);
    Ok(salt)
}

/// Read `n` bytes from the OS CSPRNG. Uses `/dev/urandom` to avoid pulling in an
/// RNG crate (the CLI targets Unix data-plane hosts).
fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    let mut buf = vec![0u8; n];
    file.read_exact(&mut buf).context("reading /dev/urandom")?;
    Ok(buf)
}

#[cfg(unix)]
fn set_permissions_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_permissions_0600(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"deterministic-test-salt";
    const ANTHROPIC_KEY: &str = "sk-ant-api03-cache-stable-abcDEF123456";
    const RRN: &str = "670125-1230644";

    fn updated_output(verdict: &Value) -> &Value {
        verdict
            .get("hookSpecificOutput")
            .and_then(|o| o.get("updatedToolOutput"))
            .expect("expected updatedToolOutput")
    }

    #[test]
    fn post_tool_use_string_response_is_redacted() {
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": format!("API_KEY={ANTHROPIC_KEY}\nrrn {RRN}\n")
        });
        let verdict = handle_hook(&payload, SALT).expect("expected a verdict");
        let out = updated_output(&verdict).as_str().unwrap();
        assert!(!out.contains(ANTHROPIC_KEY));
        assert!(!out.contains(RRN));
        assert!(out.contains("<<hs:"));
    }

    #[test]
    fn post_tool_use_object_response_is_redacted_recursively() {
        // `tool_response` shape is undocumented; an object must be walked.
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": { "content": format!("key {ANTHROPIC_KEY}"), "numLines": 1 }
        });
        let verdict = handle_hook(&payload, SALT).expect("expected a verdict");
        let content = updated_output(&verdict)
            .get("content")
            .and_then(Value::as_str)
            .unwrap();
        assert!(!content.contains(ANTHROPIC_KEY));
        assert!(content.contains("<<hs:"));
    }

    #[test]
    fn post_tool_use_clean_response_is_a_noop() {
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": "nothing sensitive here at all"
        });
        assert!(handle_hook(&payload, SALT).is_none());
    }

    #[test]
    fn post_tool_use_is_byte_deterministic() {
        // Issue #20: same payload + salt ⇒ identical redacted bytes across calls.
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "tool_response": format!("key {ANTHROPIC_KEY}")
        });
        let a = handle_hook(&payload, SALT).unwrap();
        let b = handle_hook(&payload, SALT).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn pre_tool_use_denies_sensitive_paths() {
        for path in [
            "/home/u/project/.env",
            "/home/u/project/.env.production",
            "/home/u/.ssh/id_ed25519",
            "/home/u/.aws/credentials",
            "/tmp/server.pem",
        ] {
            let payload = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": { "file_path": path }
            });
            let verdict =
                handle_hook(&payload, SALT).unwrap_or_else(|| panic!("expected deny for {path}"));
            assert_eq!(
                verdict["hookSpecificOutput"]["permissionDecision"], "deny",
                "path {path}"
            );
        }
    }

    #[test]
    fn pre_tool_use_allows_ordinary_and_template_files() {
        for path in [
            "/home/u/project/src/main.rs",
            "/home/u/project/.env.example",
            "/home/u/.ssh/id_ed25519.pub",
        ] {
            let payload = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": { "file_path": path }
            });
            assert!(
                handle_hook(&payload, SALT).is_none(),
                "path {path} should be allowed"
            );
        }
    }

    #[test]
    fn user_prompt_submit_blocks_on_secret() {
        let payload = json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": format!("deploy using {ANTHROPIC_KEY} then restart")
        });
        let verdict = handle_hook(&payload, SALT).expect("expected a block");
        assert_eq!(verdict["decision"], "block");
        assert!(
            verdict["reason"]
                .as_str()
                .unwrap()
                .contains("ANTHROPIC_KEY")
        );
    }

    #[test]
    fn user_prompt_submit_blocks_on_high_severity_pii() {
        let payload = json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": format!("my rrn is {RRN}")
        });
        let verdict = handle_hook(&payload, SALT).expect("expected a block");
        assert_eq!(verdict["decision"], "block");
    }

    #[test]
    fn user_prompt_submit_allows_clean_prompt() {
        let payload = json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "please run the test suite and fix failures"
        });
        assert!(handle_hook(&payload, SALT).is_none());
    }

    #[test]
    fn unknown_event_is_a_noop() {
        let payload = json!({ "hook_event_name": "SessionStart" });
        assert!(handle_hook(&payload, SALT).is_none());
    }

    #[test]
    fn sensitive_path_matcher_basics() {
        assert!(is_sensitive_path("/a/b/.env"));
        assert!(is_sensitive_path("C:\\proj\\secret.key"));
        assert!(is_sensitive_path("/home/u/.ssh/id_rsa"));
        assert!(!is_sensitive_path("/a/b/README.md"));
        assert!(!is_sensitive_path("/a/b/.env.sample"));
        assert!(!is_sensitive_path("/home/u/.ssh/id_rsa.pub"));
    }
}
