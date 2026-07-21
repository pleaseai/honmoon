//! `honmoon hook` — the Claude Code plugin's command-transport backend (#19).
//!
//! Reads one hook-event JSON object on stdin, runs the `honmoon-core`
//! redaction engine, and writes a non-empty hook verdict JSON to stdout. It
//! **always exits 0**: a JSON verdict on stdout with exit 0 is how a command
//! hook applies a decision; exit 2 would instead be a *blocking error* whose
//! stdout JSON Claude Code ignores. A stdout-write failure is logged rather
//! than propagated to preserve this. Unparseable stdin/JSON degrades to
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
//!   transcript). The shared core handler redacts the matched tool responses.
//! - `UserPromptSubmit`: a hook cannot rewrite a prompt, so a prompt carrying a
//!   secret or high-severity identifier is `decision:"block"`ed with an
//!   actionable reason.
//! - `PreToolUse` (matcher `Read`): deny reads of known-sensitive paths before
//!   the file is opened (so plaintext never reaches the transcript at all).

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Entry point for `honmoon hook`: read stdin, dispatch, write stdout. Never
/// fails the process for expected error conditions (see module docs).
pub fn run(salt_context: Option<&str>) -> Result<()> {
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

    let salt = session_salt(&payload, salt_context);
    let verdict = handle_hook(&payload, &salt);
    if verdict != serde_json::json!({}) {
        // Never propagate a stdout-write failure (e.g. a broken pipe if Claude
        // Code detaches early): propagating would exit non-zero and surface as a
        // hook error. Log and continue so `run` always exits 0 (module contract).
        if let Err(e) = serde_json::to_writer(std::io::stdout().lock(), &verdict) {
            eprintln!("honmoon hook: failed to write verdict to stdout ({e})");
        }
    }
    Ok(())
}

/// Resolve symlinks best-effort, then delegate the transport-independent verdict
/// to `honmoon-core`. Literal path matching remains in core; this filesystem
/// adapter keeps core free of I/O while preserving symlink protection.
///
/// This transport runs in the agent's own process, so relative paths and
/// symlinks resolve in the agent's real filesystem context. A `NotFound`
/// `canonicalize` error therefore means the file does not exist yet (the
/// legitimate new-file case) — map it to `NotSensitive` and let core's literal
/// path check apply, rather than the HTTP transport's conservative `Unresolved`
/// deny. Any *other* error (permission denied, symlink loop, …) means the
/// symlink target could not be verified, so stay conservative and report
/// `Unresolved` rather than silently treating it as not sensitive (issue #55).
pub fn handle_hook(payload: &Value, salt: &[u8]) -> Value {
    let path = payload
        .get("tool_input")
        .and_then(|input| {
            input
                .get("file_path")
                .or_else(|| input.get("notebook_path"))
        })
        .and_then(Value::as_str);
    let resolution = match path {
        None => honmoon_core::PathResolution::NotSensitive,
        // `to_string_lossy` so a non-UTF-8 path is still checked (fail toward
        // denying) rather than silently skipped by a `to_str()` `None`.
        Some(path) => match std::fs::canonicalize(path) {
            Ok(canonical) if honmoon_core::is_sensitive_path(&canonical.to_string_lossy()) => {
                honmoon_core::PathResolution::Sensitive
            }
            Ok(_) => honmoon_core::PathResolution::NotSensitive,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                honmoon_core::PathResolution::NotSensitive
            }
            Err(_) => honmoon_core::PathResolution::Unresolved,
        },
    };
    honmoon_core::claude_code_hook_verdict(payload, salt, resolution)
        .into_parts()
        .0
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
fn session_salt(payload: &Value, salt_context: Option<&str>) -> Vec<u8> {
    let env_context = std::env::var("HONMOON_HOOK_SALT_CONTEXT").ok();
    let session_context = salt_context
        .or(env_context.as_deref())
        .or_else(|| payload.get("session_id").and_then(Value::as_str))
        .unwrap_or("");
    derive_session_salt(session_context)
}

/// Derive the same per-session HMAC salt used by the command transport.
pub fn derive_salt_context(salt_context: &str) -> Vec<u8> {
    derive_session_salt(salt_context)
}

fn derive_session_salt(session_context: &str) -> Vec<u8> {
    let key = match load_or_create_machine_salt(&honmoon_dir()) {
        Ok(salt) => salt,
        Err(e) => {
            eprintln!("honmoon hook: using fallback salt ({e:#})");
            b"honmoon-hook-v1-fallback-key".to_vec()
        }
    };
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&key).expect("HMAC accepts a key of any length");
    mac.update(session_context.as_bytes());
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

    #[cfg(unix)]
    #[test]
    fn pre_tool_use_denies_when_canonicalize_fails_non_notfound() {
        // A symlink loop makes `canonicalize` fail with an error that is *not*
        // `NotFound`, so the symlink target was never verified. The command
        // transport must not treat that as the new-file case and fail open — it
        // reports `Unresolved` and core denies (the absolute-path analogue of
        // the issue #55 bypass). A genuinely missing file (`NotFound`) still
        // stays allowed for legitimate new-file writes.
        let tmp = TempDir::new("canon-loop");
        let link = tmp.path().join("config");
        std::os::unix::fs::symlink(&link, &link).expect("self-referential symlink");
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": { "file_path": link.to_string_lossy() }
        });
        let verdict = handle_hook(&payload, b"salt");
        assert_eq!(
            verdict["hookSpecificOutput"]["permissionDecision"], "deny",
            "an unverifiable path must be denied, not allowed: {verdict}"
        );

        // A path that simply does not exist is the legitimate new-file case and
        // stays allowed (a no-op verdict).
        let missing = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": tmp.path().join("brand-new.rs").to_string_lossy() }
        });
        assert_eq!(handle_hook(&missing, b"salt"), serde_json::json!({}));
    }
}
