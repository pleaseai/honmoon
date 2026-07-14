//! `honmoon hook` — the Claude Code plugin's command-transport backend (#19).
//!
//! Reads one hook-event JSON object on stdin, runs the `honmoon-core`
//! redaction engine, and writes the hook verdict JSON to stdout (or nothing
//! for a no-op). It **always exits 0**: a JSON verdict on stdout with exit 0 is
//! how a command hook applies a decision; exit 2 would instead be a *blocking
//! error* whose stdout JSON Claude Code ignores (a stdout-write failure is
//! logged, not propagated, to preserve this). Unparseable stdin/JSON degrades to
//! a no-op — content passes unredacted, since the proxy remains the enforcement
//! backstop. An unreadable/unwritable salt dir does **not** no-op: it falls back
//! to a fixed-key salt and still redacts (only placeholder unforgeability is
//! relaxed — see [`session_salt`]).
//!
//! Handlers by event:
//! - `PostToolUse` (the plugin matches `Read`, `Bash`, and `Grep` — a secret
//!   surfaced by `cat`/`grep`/`echo` lands in the same local transcript): redact
//!   the tool result via `hookSpecificOutput.updatedToolOutput` so the redacted
//!   form is what enters the model context (and, per issue #19, ideally the
//!   transcript). This handler redacts any `tool_response` regardless of tool.
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
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("honmoon hook: ignoring unreadable stdin payload ({e})");
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
        // Never propagate a stdout-write failure (e.g. a broken pipe if Claude
        // Code detaches early): propagating would exit non-zero and surface as a
        // hook error. Log and continue so `run` always exits 0 (module contract).
        if let Err(e) = serde_json::to_writer(std::io::stdout().lock(), &verdict) {
            eprintln!("honmoon hook: failed to write verdict to stdout ({e})");
        }
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

    // Dotenv, in any variant (`.env`, `.env.local`, `.env.production`), plus
    // direnv `.envrc` (commonly holds `export AWS_SECRET_ACCESS_KEY=…`).
    if base == ".env" || base == ".envrc" || base.starts_with(".env.") {
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

/// Read (or generate on first use) the persisted machine secret used as the
/// HMAC key behind placeholder unforgeability. A freshly generated secret is 32
/// bytes; the read path accepts any existing file of **at least 16 bytes** as-is
/// (a shorter/corrupt file is discarded and regenerated), and re-tightens its
/// permissions to `0600` even on that read path so a file that somehow ended up
/// group/world-readable is corrected rather than trusted indefinitely.
///
/// First-run creation is **atomic** (`O_CREAT|O_EXCL`, mode `0600`): if two hook
/// processes race on a machine with no salt yet, exactly one creates the file
/// and the other adopts the winner's bytes — so every process converges on one
/// machine key and placeholders for the same secret stay byte-stable across
/// turns (issue #20). A short/corrupt file or an unexpected read error is logged
/// before regenerating; a genuinely-absent file (first run) is silent.
fn load_or_create_machine_salt(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join("hook-salt");
    // `true` means the file exists but is unusable (must be force-overwritten);
    // `false` means it is absent (first run — create atomically to avoid a race).
    let must_overwrite = match std::fs::read(&path) {
        Ok(bytes) if bytes.len() >= 16 => {
            // Valid: adopt it, but correct its permissions in case an external
            // actor (backup restore, older build) left it looser than 0600.
            set_permissions_0600(&path);
            return Ok(bytes);
        }
        Ok(bytes) => {
            eprintln!(
                "honmoon hook: salt file {} is short/corrupt ({} bytes) — regenerating",
                path.display(),
                bytes.len()
            );
            true
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            eprintln!(
                "honmoon hook: unexpected error reading salt file {} ({e}) — regenerating",
                path.display()
            );
            true
        }
        Err(_) => false, // NotFound: expected on first use, no diagnostic needed.
    };

    let salt = random_bytes(32)?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    if must_overwrite {
        // The file exists but is unusable, so there is no create race to lose:
        // overwrite it. (A concurrent second corrupt-recovery is negligible — the
        // damaged state is already anomalous.)
        write_secret_file(&path, &salt).with_context(|| format!("writing {}", path.display()))?;
        return Ok(salt);
    }

    // First use: create exclusively so a concurrent first-run process cannot
    // persist a *different* machine key. If we lose the race, read and adopt the
    // winner's salt instead of our own.
    match create_secret_file_exclusive(&path, &salt) {
        Ok(()) => Ok(salt),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match std::fs::read(&path) {
            Ok(bytes) if bytes.len() >= 16 => Ok(bytes),
            // The winner wrote something unusable (or it vanished): fall back to
            // our own salt for this call rather than fail. Redaction still works;
            // only cross-process convergence is briefly relaxed.
            _ => Ok(salt),
        },
        Err(e) => Err(e).with_context(|| format!("writing {}", path.display())),
    }
}

/// Write `bytes` to `path`, creating it `0600` (Unix) via the open mode so the
/// secret is never briefly readable at the umask default between `write` and a
/// later `chmod`. Truncates an existing file, and re-tightens permissions
/// afterward since open-mode applies only on creation.
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    set_permissions_0600(path);
    Ok(())
}

/// Create `path` **exclusively** (`O_CREAT|O_EXCL`, mode `0600` on Unix), failing
/// with [`std::io::ErrorKind::AlreadyExists`] if it already exists so the caller
/// can detect and recover from a lost create race. No `chmod` afterward: an
/// exclusively-created file is new, so the open-mode `0600` is authoritative.
fn create_secret_file_exclusive(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    Ok(())
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
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!(
            "honmoon hook: could not restrict permissions on {} ({e}) — salt may be group/world-readable",
            path.display()
        );
    }
}

#[cfg(not(unix))]
fn set_permissions_0600(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use honmoon_core::PLACEHOLDER_PREFIX;

    const SALT: &[u8] = b"deterministic-test-salt";
    const ANTHROPIC_KEY: &str = "sk-ant-api03-cache-stable-abcDEF123456";
    const RRN: &str = "670125-1230644";

    /// Throwaway temp dir under the OS temp root, removed on drop. The `tag`
    /// keeps concurrently-running tests from colliding on the same path (no
    /// `tempfile` dev-dependency in this workspace).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("honmoon-hook-test-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("creating temp dir");
            TempDir(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

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
        assert!(out.contains(PLACEHOLDER_PREFIX));
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
        assert!(content.contains(PLACEHOLDER_PREFIX));
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
    fn sensitive_path_matcher_covers_deny_list() {
        // Every dotenv variant, credential basename, key extension, and path
        // fragment must match — case-insensitively, across `/` and `\`.
        let sensitive = [
            "/a/b/.env",
            "/a/b/.env.local",
            "/a/b/.env.production",
            "/a/b/.envrc",
            "/a/b/.git-credentials",
            "/a/b/.netrc",
            "/a/b/.npmrc",
            "/a/b/.pypirc",
            "/a/b/credentials",
            "/home/u/.ssh/id_rsa",
            "/home/u/.ssh/id_dsa",
            "/home/u/.ssh/id_ecdsa",
            "/home/u/.ssh/id_ed25519",
            "/tmp/server.pem",
            "/tmp/server.key",
            "/tmp/bundle.p12",
            "/tmp/bundle.pfx",
            "/tmp/store.keystore",
            "/tmp/store.jks",
            "/tmp/key.asc",
            "C:\\proj\\secret.key",       // backslash separator
            "/home/u/.aws/credentials",   // path fragment
            "/home/u/.gnupg/secring.gpg", // path fragment
            "/a/b/.ENV",                  // case-insensitive basename
            "/tmp/SERVER.PEM",            // case-insensitive extension
        ];
        for path in sensitive {
            assert!(is_sensitive_path(path), "{path} should be sensitive");
        }

        // Ordinary source, template/sample files, and public key material must
        // stay readable (templates hold no real secret; `.pub`/`known_hosts`/
        // `config` under `.ssh` are not secret).
        let allowed = [
            "/a/b/README.md",
            "/a/b/.env.example",
            "/a/b/.env.sample",
            "/a/b/config.template",
            "/a/b/schema.dist",
            "/home/u/.ssh/id_rsa.pub",
            "/home/u/.ssh/known_hosts",
            "/home/u/.ssh/config",
        ];
        for path in allowed {
            assert!(!is_sensitive_path(path), "{path} should be allowed");
        }
    }

    #[test]
    fn redact_json_value_walks_arrays_and_nested_fields() {
        let value = json!({
            "lines": [format!("first {ANTHROPIC_KEY}"), "clean line", format!("rrn {RRN}")],
            "meta": { "note": format!("token {ANTHROPIC_KEY}"), "count": 3 },
            "ok": true
        });
        let (redacted, changed) = redact_json_value(&value, SALT);
        assert!(changed);
        let blob = redacted.to_string();
        assert!(!blob.contains(ANTHROPIC_KEY), "every string leaf redacted");
        assert!(!blob.contains(RRN));
        // Non-string leaves survive verbatim, and a clean element is untouched.
        assert_eq!(redacted["meta"]["count"], 3);
        assert_eq!(redacted["ok"], true);
        assert_eq!(redacted["lines"][1], "clean line");
    }

    #[test]
    fn redact_json_value_reports_unchanged_when_clean() {
        let value = json!({ "lines": ["all", "clean"], "n": 1, "ok": false });
        let (redacted, changed) = redact_json_value(&value, SALT);
        assert!(!changed, "a clean value must not report a change");
        assert_eq!(redacted, value);
    }

    #[test]
    fn machine_salt_persists_and_is_stable() {
        let tmp = TempDir::new("persist");
        let first = load_or_create_machine_salt(tmp.path()).expect("first load");
        assert_eq!(first.len(), 32, "a freshly generated salt is 32 bytes");
        let second = load_or_create_machine_salt(tmp.path()).expect("second load");
        assert_eq!(first, second, "second call reuses the persisted salt");
    }

    #[test]
    fn machine_salt_regenerates_short_or_corrupt_file() {
        let tmp = TempDir::new("corrupt");
        std::fs::write(tmp.path().join("hook-salt"), b"tooshort").expect("seed corrupt file");
        let salt = load_or_create_machine_salt(tmp.path()).expect("regenerate");
        assert!(
            salt.len() >= 16,
            "a short file is discarded and regenerated"
        );
        assert_ne!(salt, b"tooshort".to_vec(), "not the corrupt bytes");
        // The regenerated salt is itself persisted and stable thereafter.
        assert_eq!(
            salt,
            load_or_create_machine_salt(tmp.path()).expect("reload")
        );
    }

    #[cfg(unix)]
    #[test]
    fn machine_salt_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new("perms");
        load_or_create_machine_salt(tmp.path()).expect("create salt");
        let mode = std::fs::metadata(tmp.path().join("hook-salt"))
            .expect("stat salt file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "salt file must be owner-only (0600)");
    }

    #[cfg(unix)]
    #[test]
    fn machine_salt_read_path_retightens_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new("retighten");
        let path = tmp.path().join("hook-salt");
        std::fs::write(&path, [7u8; 32]).expect("seed valid salt");
        // Simulate a file left group/world-readable by some external actor.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen perms");
        let salt = load_or_create_machine_salt(tmp.path()).expect("load");
        assert_eq!(
            salt,
            vec![7u8; 32],
            "a valid existing salt is adopted as-is"
        );
        let mode = std::fs::metadata(&path)
            .expect("stat salt file")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "loose permissions are re-tightened on the read path"
        );
    }
}
