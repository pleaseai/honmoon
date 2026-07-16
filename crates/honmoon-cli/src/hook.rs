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
    // Deny when either the requested path OR its symlink-resolved target is
    // sensitive: a benign-looking name (`config` → `.env`) must not smuggle a
    // credential file past the deny list. Resolution is best-effort — if the path
    // can't be canonicalized (doesn't exist yet, permission error), fall back to
    // the literal check already performed, never failing open more than the
    // pre-symlink behavior did.
    let resolved_is_sensitive = std::fs::canonicalize(file_path)
        .ok()
        .and_then(|p| p.to_str().map(is_sensitive_path))
        .unwrap_or(false);
    if !is_sensitive_path(file_path) && !resolved_is_sensitive {
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
    // Scan at the HIGH floor so `outcome.labels()` lists only what actually
    // blocks. MEDIUM PII (EMAIL/PHONE) never blocks a prompt on its own, so
    // naming it in the reason would wrongly imply the user must strip their email
    // to resubmit. This handler only reads the labels/severity to decide the
    // block — it never emits `outcome.text` (a prompt-submit hook cannot rewrite
    // the prompt), so the narrower scan weakens no redaction.
    let outcome = redact(prompt, salt, PII_SEVERITY_HIGH);
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

/// Maximum JSON nesting depth [`redact_json_value`] descends into. Real Claude
/// Code tool output is never legitimately this deep; a pathologically nested
/// payload must not exhaust the thread stack and turn a graceful no-op into a
/// non-zero hook error (the process exits per hook call).
const MAX_REDACT_DEPTH: usize = 64;

/// Replacement emitted for a subtree that exceeds [`MAX_REDACT_DEPTH`]. Contains
/// the placeholder marker `redacted` so it can never itself be re-flagged as a
/// secret, and carries no scannable content.
const DEPTH_LIMIT_MARKER: &str = "[honmoon: redacted — nesting exceeds scan depth]";

/// Recursively redact every string leaf of a JSON value, returning the redacted
/// value and whether anything changed. Descent is bounded by [`MAX_REDACT_DEPTH`].
fn redact_json_value(value: &Value, salt: &[u8]) -> (Value, bool) {
    redact_json_value_at(value, salt, 0)
}

fn redact_json_value_at(value: &Value, salt: &[u8], depth: usize) -> (Value, bool) {
    if depth >= MAX_REDACT_DEPTH {
        // Too deep to scan safely. Fail CLOSED, not open: a redactor that passed
        // an unscanned subtree through would leak any secret buried below the cap
        // (a depth this large is not real tool output, so we do not rely on that
        // assumption for safety). Replace the whole subtree with a non-secret
        // marker and report a change so the redacted form is what is emitted —
        // over-redacting pathological nesting is the safe default, and it still
        // avoids the stack overflow that a non-zero hook error would come from.
        return (Value::String(DEPTH_LIMIT_MARKER.to_string()), true);
    }
    match value {
        Value::String(s) => {
            let outcome = redact(s, salt, DEFAULT_MIN_PII_SEVERITY);
            (Value::String(outcome.text), outcome.redacted)
        }
        Value::Array(items) => {
            let mut changed = false;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let (redacted, item_changed) = redact_json_value_at(item, salt, depth + 1);
                changed |= item_changed;
                out.push(redacted);
            }
            (Value::Array(out), changed)
        }
        Value::Object(map) => {
            let mut changed = false;
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, val) in map {
                let (redacted, val_changed) = redact_json_value_at(val, salt, depth + 1);
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
/// First-run publish is **atomic** — a fully-written temp file linked into place
/// with `hard_link` (see [`publish_secret_atomically`]). If two hook processes
/// race on a machine with no salt yet, the target only ever appears
/// already-complete, exactly one publisher wins the link, and every loser adopts
/// the winner's bytes in a single read — so every process converges on one
/// machine key and placeholders for the same secret stay byte-stable across turns
/// (issue #20), with no empty-file window and no read-retry loop. A short/corrupt
/// file or an unexpected read error is logged before regenerating; a
/// genuinely-absent file (first run) is silent.
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

    // First use: publish atomically so a concurrent first-run process cannot
    // persist a *different* machine key, and so the target file is never visible
    // in a half-written state. If we lose the link race, adopt the winner's salt.
    publish_secret_atomically(dir, &path, &salt)
}

/// Publish `salt` as the first-run machine key: write it to an
/// exclusively-created temp with an unpredictable name, then `hard_link` that
/// temp onto `path`. Two properties combine here:
/// - **Atomic publish** — `hard_link` is one syscall that fails with
///   [`std::io::ErrorKind::AlreadyExists`] if the target exists, so exactly one
///   racer publishes and the target only ever becomes visible already-complete (a
///   publisher links *after* its temp is fully written). A loser reads the
///   winner's bytes in a single shot — no empty-file window, no read-retry loop.
/// - **Exclusive, unguessable temp write** — the temp is created with
///   `O_CREAT|O_EXCL` (mode `0600`) at a random name, so the write neither follows
///   nor clobbers a *pre-planted* symlink/file, and no two racers collide. This
///   restores the pre-planting safety the removed exclusive first-run create had.
///   (It does not fully close a hostile-directory attack: in an attacker-writable,
///   *observable* `dir` an attacker could still replace the temp between its close
///   and the `hard_link` — a TOCTOU that only fd-based linking or a trusted,
///   non-attacker-writable directory would eliminate. The default `$HOME/.honmoon`
///   is user-owned, so this residual gap is out of the standard threat model.)
///
/// Falls back to the caller's own (unpersisted) `salt` only if the post-link read
/// genuinely fails; the next invocation self-heals via the short-file path.
fn publish_secret_atomically(dir: &Path, path: &Path, salt: &[u8]) -> Result<Vec<u8>> {
    // Unpredictable temp name (16 random bytes), created exclusively below: an
    // attacker cannot pre-plant a file/symlink at a path they cannot guess, and no
    // two racers (processes or threads) collide on it.
    let nonce = random_bytes(16)?;
    let tmp = dir.join(format!("hook-salt.tmp.{}", hex_encode(&nonce)));
    if let Err(e) = create_secret_file_exclusive(&tmp, salt)
        .with_context(|| format!("writing temp salt {}", tmp.display()))
    {
        // A write failure after the exclusive create leaves a partial/empty temp.
        // It is ours alone (random nonce), so remove it before returning rather
        // than accumulating orphaned salt material in `dir` on repeated I/O errors.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    let linked = std::fs::hard_link(&tmp, path);
    // The temp has done its job in every outcome — remove it. On a win its content
    // now lives at `path` via the link; on a loss `path` already holds the winner's
    // content. A cleanup failure is non-fatal but leaves a 0600 secret file behind,
    // so log it (this file treats every non-happy filesystem anomaly as log-worthy).
    // `NotFound` is not such an anomaly — the temp is already gone, nothing lingers.
    if let Err(e) = std::fs::remove_file(&tmp) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "honmoon hook: could not remove temp salt file {} ({e}) — secret material may linger on disk",
                tmp.display()
            );
        }
    }

    match linked {
        Ok(()) => Ok(salt.to_vec()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost the race: the target is already a complete salt (a publisher
            // links only after a full write), so a single read suffices. The two
            // anomaly arms below are "vanishingly unlikely" (target present but
            // short/unreadable right after a peer's link) — fall back to our own
            // salt for this one invocation, but log it, mirroring the sibling read
            // path in `load_or_create_machine_salt`: the next run self-heals via
            // the top-level path, so without a diagnostic a transient recurrence
            // would leave no trace at all.
            match std::fs::read(path) {
                Ok(bytes) if bytes.len() >= 16 => Ok(bytes),
                Ok(bytes) => {
                    eprintln!(
                        "honmoon hook: winner salt file {} is short/corrupt ({} bytes) after a lost publish race — using our own salt for this invocation",
                        path.display(),
                        bytes.len()
                    );
                    Ok(salt.to_vec())
                }
                Err(e) => {
                    eprintln!(
                        "honmoon hook: unexpected error reading salt file {} after a lost publish race ({e}) — using our own salt for this invocation",
                        path.display()
                    );
                    Ok(salt.to_vec())
                }
            }
        }
        Err(e) => Err(e).with_context(|| format!("linking salt into place {}", path.display())),
    }
}

/// Create `path` **exclusively** (`O_CREAT|O_EXCL`, mode `0600` on Unix), failing
/// with [`std::io::ErrorKind::AlreadyExists`] if it already exists. Exclusive
/// creation refuses to follow or truncate a pre-planted symlink/file, so it is
/// symlink-safe; no `chmod` afterward since a newly created file already carries
/// the authoritative open-mode `0600`.
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

/// Lowercase hex-encode `bytes` (the workspace pulls in no `hex` crate). Used only
/// for the random temp-file suffix in [`publish_secret_atomically`].
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
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

/// Read `n` bytes from the OS CSPRNG. Uses `/dev/urandom` to avoid pulling in an
/// RNG crate (the CLI targets Unix data-plane hosts). Guarded `#[cfg(unix)]` to
/// match `set_permissions_0600` and the `OpenOptionsExt` open modes elsewhere in
/// this file, so non-Unix builds fail explicitly here rather than compiling
/// cleanly and degrading silently to the fallback key at runtime.
#[cfg(unix)]
fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    let mut buf = vec![0u8; n];
    file.read_exact(&mut buf).context("reading /dev/urandom")?;
    Ok(buf)
}

/// Non-Unix hosts have no `/dev/urandom`; the hook targets Unix data-plane hosts.
/// Surface a clear error so the caller enters the fallback-salt path deliberately
/// (per the fail-open contract) instead of via an opaque file-open failure.
#[cfg(not(unix))]
fn random_bytes(_n: usize) -> Result<Vec<u8>> {
    anyhow::bail!("/dev/urandom CSPRNG is unavailable on non-Unix hosts")
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

    #[cfg(unix)]
    #[test]
    fn pre_tool_use_denies_symlink_to_sensitive_target() {
        use std::os::unix::fs::symlink;
        // A benign-looking name pointing at a credential file (`config` → `.env`)
        // must be denied via symlink resolution, not just the literal basename.
        let tmp = TempDir::new("symlink");
        let target = tmp.path().join(".env");
        std::fs::write(&target, "SECRET=x").expect("write .env target");
        let link = tmp.path().join("config");
        symlink(&target, &link).expect("create symlink");
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": { "file_path": link.to_str().unwrap() }
        });
        let verdict = handle_hook(&payload, SALT).expect("expected deny for symlink to .env");
        assert_eq!(
            verdict["hookSpecificOutput"]["permissionDecision"], "deny",
            "a symlink resolving to a sensitive file must be denied"
        );
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
    fn user_prompt_submit_reason_omits_non_blocking_medium_pii() {
        // A secret blocks the prompt; a co-occurring MEDIUM email does not and
        // must not appear in the reason (else the user is told to strip an email
        // that was never the blocker).
        let payload = json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": format!("email me at alice@corp.io using {ANTHROPIC_KEY}")
        });
        let verdict = handle_hook(&payload, SALT).expect("expected a block");
        let reason = verdict["reason"].as_str().unwrap();
        assert!(reason.contains("ANTHROPIC_KEY"), "blocking secret is named");
        assert!(
            !reason.contains("EMAIL"),
            "non-blocking medium PII must be omitted from the reason"
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
    fn redact_json_value_fails_closed_beyond_depth_cap() {
        // A pathologically deep payload must return gracefully instead of
        // overflowing the stack, AND must fail closed: a secret nested below
        // MAX_REDACT_DEPTH is replaced wholesale (never passed through), and the
        // call reports a change so the redacted form is what gets emitted.
        let mut v = json!(format!("deep {ANTHROPIC_KEY}"));
        for _ in 0..(MAX_REDACT_DEPTH + 50) {
            v = json!([v]);
        }
        let (redacted, changed) = redact_json_value(&v, SALT);
        assert!(changed, "crossing the depth cap must report a change");
        assert!(
            !redacted.to_string().contains(ANTHROPIC_KEY),
            "a secret below the cap must not survive — fail closed"
        );
        assert!(
            redacted.to_string().contains(DEPTH_LIMIT_MARKER),
            "the too-deep subtree is replaced with the redaction marker"
        );
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

    #[test]
    fn first_run_loser_adopts_complete_winner_salt() {
        // A publisher that loses the link race must adopt the winner's *complete*
        // bytes in one read. The hard_link publish makes the target appear only
        // once fully written, so there is no empty-file window and no retry loop:
        // pre-seed the target as the winner would, publish our own salt, and
        // confirm we return the winner's bytes — never our own unpersisted salt.
        let tmp = TempDir::new("loser");
        let path = tmp.path().join("hook-salt");
        let winner = vec![9u8; 32];
        std::fs::write(&path, &winner).expect("winner publishes first");
        let ours = vec![1u8; 32];
        let adopted =
            publish_secret_atomically(tmp.path(), &path, &ours).expect("publish loses the race");
        assert_eq!(
            adopted, winner,
            "loser adopts the winner's bytes, not its own"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            winner,
            "the winner's file is left untouched"
        );
    }

    #[test]
    fn first_run_loser_falls_back_when_winner_file_is_short() {
        // The lost-race read normally sees a complete winner file; the fallback
        // arm only fires in the "vanishingly unlikely" case that the target is
        // present but under 16 bytes right after a peer's link. Exercise it
        // deterministically: pre-seed `path` with a sub-16-byte file so the
        // hard_link loses (target exists) and the follow-up read is too short —
        // the publisher must fall back to its own salt for this invocation rather
        // than erroring or returning garbage.
        let tmp = TempDir::new("short-winner");
        let path = tmp.path().join("hook-salt");
        std::fs::write(&path, b"tooshort").expect("seed short winner file");
        let ours = vec![1u8; 32];
        let adopted =
            publish_secret_atomically(tmp.path(), &path, &ours).expect("publish falls back");
        assert_eq!(
            adopted, ours,
            "a short winner file forces fallback to our own salt"
        );
    }

    #[test]
    fn machine_salt_concurrent_first_run_converges_to_one_key() {
        // Many first-run publishers racing on an empty dir must all converge on a
        // single persisted key — issue #20 byte-stability depends on it. With the
        // hard_link publish the winner's file is visible only once complete, so no
        // racer observes an empty file or falls back to an unpersisted salt.
        let tmp = TempDir::new("race");
        let dir = tmp.path().to_path_buf();
        const THREADS: usize = 16;
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || load_or_create_machine_salt(&dir).expect("load salt"))
            })
            .collect();
        let salts: Vec<Vec<u8>> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect();

        let winner = &salts[0];
        assert_eq!(
            winner.len(),
            32,
            "the converged salt is a freshly generated 32 bytes"
        );
        for s in &salts {
            assert_eq!(s, winner, "every racer converged on the one persisted key");
        }
        assert_eq!(
            &std::fs::read(dir.join("hook-salt")).expect("read persisted salt"),
            winner,
            "the persisted file is exactly the converged key"
        );

        // Every publisher removes its own temp, so none linger after the race.
        let leftover_temps = std::fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("hook-salt.tmp.")
            })
            .count();
        assert_eq!(leftover_temps, 0, "temp files are cleaned up after publish");
    }
}
