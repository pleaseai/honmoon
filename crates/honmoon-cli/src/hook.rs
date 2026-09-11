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
//! relaxed — see [`machine_key`]), and records that degradation in the audit log
//! when one is configured (`--audit-log` / `HONMOON_AUDIT_LOG`), since a
//! non-interactive hook's stderr reaches nobody.
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
use serde_json::Value;

/// Entry point for `honmoon hook`: read stdin, dispatch, write stdout. Never
/// fails the process for expected error conditions (see module docs).
///
/// `audit_log`, when given, is the JSONL file a fallback machine key is reported
/// to (see [`record_machine_key_source`]); without it the degradation still only
/// reaches stderr.
pub fn run(salt_context: Option<&str>, audit_log: Option<&Path>) -> Result<()> {
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

    let machine_key = machine_key();
    audit_machine_key_status(audit_log, &machine_key.status);
    let salt = session_salt(&payload, salt_context, &machine_key);
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
/// symlinks resolve in the agent's real filesystem context. Only a path that is
/// genuinely absent (confirmed via `symlink_metadata`, which does not follow the
/// final component) is the legitimate new-file case → `NotSensitive`, letting
/// core's literal path check apply. A `canonicalize` `NotFound` on an *existing*
/// dangling symlink, or any other error (permission denied, symlink loop, …),
/// means the target could not be verified, so report `Unresolved` rather than
/// silently treating it as not sensitive (issue #55).
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
                // `canonicalize` also returns `NotFound` for an *existing* dangling
                // symlink (link present, target missing) — a `Write` through it
                // would create the hidden target, so it must not be treated as a
                // new file. `symlink_metadata` does not follow the final component:
                // `NotFound` there means the path genuinely does not exist (the
                // legitimate new-file case); anything else means it exists but
                // could not be verified — stay conservative (issue #55).
                match std::fs::symlink_metadata(path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        honmoon_core::PathResolution::NotSensitive
                    }
                    _ => honmoon_core::PathResolution::Unresolved,
                }
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
/// machine salt stays secret.
///
/// The context precedence and the derivation itself live in `honmoon-core` so
/// the management endpoint keys the identical salt for the identical session
/// (#98): a session that mixes transports must not mint two placeholders for
/// one secret.
fn session_salt(payload: &Value, salt_context: Option<&str>, machine_key: &MachineKey) -> Vec<u8> {
    let env_context = std::env::var("HONMOON_HOOK_SALT_CONTEXT").ok();
    let pinned = salt_context.or(env_context.as_deref());
    honmoon_core::derive_hook_salt(
        machine_key.as_slice(),
        honmoon_core::hook_salt_context(pinned, payload),
    )
}

/// The key used when the persisted machine secret is unavailable. Public by
/// construction — it ships in the binary and in this repository's source — so
/// every placeholder minted under it is forgeable by anyone (see
/// [`MachineKeySource::Fallback`]).
const FALLBACK_MACHINE_KEY: &[u8] = b"honmoon-hook-v1-fallback-key";

/// `rule` on a degraded event whose key is not the persisted one — the
/// per-invocation [`MachineKeySource::Unpersisted`] salt, or
/// [`FALLBACK_MACHINE_KEY`]. `key_source` distinguishes the two.
const HOOK_SALT_FALLBACK_RULE: &str = "hook-salt-fallback";

/// `rule` on a degraded event whose key *is* the persisted one but whose file is
/// readable beyond its owner (issue #141).
///
/// A separate rule rather than a fourth [`honmoon_core::RedactionKeySource`]:
/// exposure and provenance are independent axes, and the key on this path really
/// did come from `~/.honmoon/hook-salt`, so a `key_source` of anything but
/// `persisted` would be false. `rule` is where "which degradation is this"
/// already lives on every audit event.
const HOOK_SALT_EXPOSED_RULE: &str = "hook-salt-exposed";

/// Where the bytes in a [`MachineKey`] came from — one of the two axes worth
/// recording about a key. Who else can read them is the other, and it lives on
/// [`MachineKeyStatus::exposure`] rather than here (issue #141): a key can
/// genuinely be the persisted one *and* be group/world-readable, so a fourth
/// variant folding the two together would have to lie about one of them.
pub enum MachineKeySource {
    /// The random secret persisted at `~/.honmoon/hook-salt`.
    ///
    /// Attests where the bytes came from, not who else can read them —
    /// [`MachineKeyStatus::exposure`] carries that, recorded alongside rather
    /// than folded in here.
    Persisted,
    /// A private random secret that could not be persisted, so it is this
    /// process's alone. `reason` is why it did not reach disk.
    ///
    /// Unforgeability survives — the bytes are random and secret — but
    /// byte-stability does not: the next invocation derives a different salt,
    /// so one secret mints a different placeholder each turn and the prompt
    /// cache prefix breaks (issue #20), while the other transport disagrees
    /// outright (#98). Distinguished from [`Self::Fallback`] because the two
    /// lose different guarantees, and from [`Self::Persisted`] because
    /// labelling it that would be false — the whole point of recording
    /// provenance is that the label is true.
    Unpersisted { reason: String },
    /// [`FALLBACK_MACHINE_KEY`], because the persisted secret could not be read
    /// or created. `reason` is the loader's error chain.
    ///
    /// On this path placeholder unforgeability is not weakened but absent: the
    /// key is published, so anyone can mint the placeholder a guessed secret
    /// would produce for a given session and check it against a redacted
    /// transcript. It is also invisible from the outside — placeholders keep
    /// their shape, keep restoring, and two processes that both fall back agree
    /// with each other, so cross-transport parity holds while the property it
    /// protects is gone. [`record_machine_key_source`] is what makes it visible.
    Fallback { reason: String },
}

/// Everything about a machine key that is worth recording: where its bytes came
/// from, and what the loader observed about who else can read them.
///
/// Two fields rather than one wider enum, because the two are orthogonal — a key
/// can genuinely be the persisted one *and* have been left group/world-readable
/// (issue #141). Folding exposure into [`MachineKeySource`] would make whichever
/// variant won the fold false about the other axis.
pub struct MachineKeyStatus {
    /// Which key this is.
    pub source: MachineKeySource,
    /// `Some(reason)` when the salt file behind a [`MachineKeySource::Persisted`]
    /// key is readable beyond its owner *after* the loader tried to restrict it,
    /// `reason` naming the mode observed.
    ///
    /// The observed mode is the claim, deliberately, and it is narrower than it
    /// looks in both directions. A `chmod` that fails is not evidence of
    /// exposure — a read-only mount refuses the call on a file that is already
    /// `0600`, and recording that would be a false alarm in the one channel that
    /// must stay worth reading. A `chmod` that succeeds is not evidence of
    /// safety either: it closes the window going forward and says nothing about
    /// who read the file before. So `None` attests "owner-only when the loader
    /// looked", never "never exposed".
    pub exposure: Option<String>,
}

impl MachineKeyStatus {
    /// Whether there is anything to record — a key that is not the persisted
    /// one, or a persisted one whose file was readable beyond its owner.
    fn is_degraded(&self) -> bool {
        !matches!(self.source, MachineKeySource::Persisted) || self.exposure.is_some()
    }
}

/// The machine secret that keys every hook salt derivation, plus what is worth
/// recording about it.
///
/// The two travel together and are constructed together, so a caller cannot
/// label one key's bytes with another key's status — the whole point of this
/// type is that the recorded degradation matches the key actually in use. The
/// bytes stay private for the reason [`honmoon_mgmt::HookSalt`]'s `HookKey`
/// keeps its own private: key material has no business on a public field.
pub struct MachineKey {
    bytes: Vec<u8>,
    status: MachineKeyStatus,
}

impl MachineKey {
    /// The key material, for HMAC derivation.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Split the key into its bytes and its status, for a caller that must own
    /// both — the gateway hands the bytes to the management endpoint, which
    /// derives per request, and keeps the status to record after startup.
    pub fn into_parts(self) -> (Vec<u8>, MachineKeyStatus) {
        (self.bytes, self.status)
    }
}

/// The persisted machine secret that keys every hook salt derivation, for the
/// gateway to hand to the management endpoint (which derives per request).
///
/// Falls back to a fixed key if the salt file can't be read/written, which
/// keeps redaction working and deterministic — only the unforgeability property
/// is relaxed, and both transports relax it identically. That fail-open contract
/// is deliberate and unchanged; the returned [`MachineKey::source`] is what lets
/// a caller record the degradation somewhere durable (issue #131).
pub fn machine_key() -> MachineKey {
    machine_key_in(&honmoon_dir())
}

/// [`machine_key`] against an explicit directory, so the fallback path is
/// reachable from a test without touching `HOME`.
fn machine_key_in(dir: &Path) -> MachineKey {
    match load_or_create_machine_salt(dir) {
        Ok(LoadedSalt {
            bytes,
            unpersisted,
            exposed,
        }) => MachineKey {
            bytes,
            status: MachineKeyStatus {
                source: match unpersisted {
                    Some(reason) => MachineKeySource::Unpersisted { reason },
                    None => MachineKeySource::Persisted,
                },
                exposure: exposed,
            },
        },
        Err(e) => {
            eprintln!("honmoon hook: using fallback salt ({e:#})");
            MachineKey {
                bytes: FALLBACK_MACHINE_KEY.to_vec(),
                status: MachineKeyStatus {
                    source: MachineKeySource::Fallback {
                        reason: format!("{e:#}"),
                    },
                    // No salt file was adopted, so there is no mode to observe.
                    exposure: None,
                },
            }
        }
    }
}

/// Record a machine key the engine should not be running on; a healthy key —
/// the persisted one, owner-only when the loader looked — records nothing, so
/// presence in the log is itself the signal.
///
/// Which degradation it is comes off `rule`, the discriminator every other audit
/// event already carries: [`HOOK_SALT_FALLBACK_RULE`] for a key that is not the
/// persisted one, [`HOOK_SALT_EXPOSED_RULE`] for a persisted key whose file is
/// readable beyond its owner. On the fallback rule `key_source` then says which
/// guarantee was lost — unforgeability under [`MachineKeySource::Fallback`],
/// byte-stability under [`MachineKeySource::Unpersisted`]. On the exposure rule
/// it stays `persisted`, because that is what the key is.
///
/// The audit log is the one channel in this system a human reviews after the
/// fact — a JSONL file the query API and the dashboard read — which is what the
/// single `eprintln!` on the fallback path is not: `honmoon hook` runs
/// non-interactively under the agent, so its stderr usually reaches nobody.
/// One event per derivation, deliberately: on a host that cannot persist a salt
/// every invocation is separately degraded, and a log that says so once would
/// understate how much of a transcript was redacted under a public key.
///
/// Returns whether the durable sink took the record — `Ok(())` when the key was
/// persisted and there was nothing to say. The caller must not discard an
/// `Err`: this record is the degradation's only durable trace, so a sink that
/// refused it has to be reported through whatever channel that caller does have.
pub fn record_machine_key_status(
    audit: &honmoon_core::AuditLog,
    transport: honmoon_core::RedactionTransport,
    status: &MachineKeyStatus,
) -> std::io::Result<()> {
    let (key_source, rule, reason) = match (&status.source, &status.exposure) {
        (MachineKeySource::Persisted, None) => return Ok(()),
        // The key genuinely is the persisted one, so `key_source` stays true and
        // `rule` carries the orthogonal bad news (issue #141).
        (MachineKeySource::Persisted, Some(reason)) => (
            honmoon_core::RedactionKeySource::Persisted,
            HOOK_SALT_EXPOSED_RULE,
            reason,
        ),
        // A key that never reached disk, and the compiled-in constant, have no
        // adopted salt file whose mode could have been observed — `exposure` is
        // `None` on both by construction, which is why these arms ignore it.
        (MachineKeySource::Unpersisted { reason }, _) => (
            honmoon_core::RedactionKeySource::Unpersisted,
            HOOK_SALT_FALLBACK_RULE,
            reason,
        ),
        (MachineKeySource::Fallback { reason }, _) => (
            honmoon_core::RedactionKeySource::Fallback,
            HOOK_SALT_FALLBACK_RULE,
            reason,
        ),
    };
    let (_, written) = audit.record_durable(honmoon_core::AuditDraft {
        decision: honmoon_core::Decision::Degraded,
        // What happened to the traffic, not to the guarantee: nothing was
        // blocked — redaction ran and content went through (the fail-open
        // contract). The `degraded` decision carries the bad news.
        verdict: honmoon_core::Verdict::Allow,
        rule: Some(rule.to_string()),
        facts: honmoon_core::FactsSummary {
            redaction: Some(honmoon_core::RedactionFacts {
                key_source,
                transport,
                reason: reason.clone(),
            }),
            ..Default::default()
        },
        approval_id: None,
    });
    written
}

/// Report a degraded machine key to `audit_log`, the hook transport's only
/// durable channel — it is a fresh process per invocation, so it holds no
/// in-memory ring anyone could query.
///
/// The sink must be configured (`--audit-log`, or `HONMOON_AUDIT_LOG` for the
/// agent environment, which is all the plugin's dispatcher can pass). It
/// deliberately does not default under `~/.honmoon`: an unwritable `~/.honmoon`
/// is one of the conditions that produces a fallback key in the first place, so
/// that default would be unwritable exactly when it had something to say. Every
/// failure here is swallowed after a stderr line — the fail-open contract owns
/// this process, and reporting a degradation must not itself become one.
fn audit_machine_key_status(audit_log: Option<&Path>, status: &MachineKeyStatus) {
    if !status.is_degraded() {
        return;
    }
    let Some(path) = audit_log else {
        return;
    };
    // Opened-then-failed earns the same line as never-opened: this process keeps
    // no ring anyone can query afterwards, and with no `RUST_LOG` its `tracing`
    // warnings are filtered out before they are written — so when the sink does
    // not take the record, stderr is all that is left.
    let recorded = honmoon_core::AuditLog::with_file(1, path).and_then(|audit| {
        record_machine_key_status(&audit, honmoon_core::RedactionTransport::Hook, status)
    });
    if let Err(e) = recorded {
        eprintln!(
            "honmoon hook: could not record the degraded salt in {} ({e}) — reported to stderr only",
            path.display()
        );
    }
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
struct LoadedSalt {
    bytes: Vec<u8>,
    /// `Some(reason)` when these bytes never reached disk, so the next
    /// invocation will derive a different salt. The loader reports it rather
    /// than returning a bare success, because "we produced a key" and "the key
    /// is the one every other process will read" are different facts and only
    /// the second one keeps placeholders stable (issues #20, #98).
    unpersisted: Option<String>,
    /// `Some(reason)` when the salt file is readable beyond its owner after the
    /// loader tried to restrict it — see [`MachineKeyStatus::exposure`], which
    /// this becomes. Orthogonal to `unpersisted`: it is the file's mode, not the
    /// bytes' provenance.
    exposed: Option<String>,
}

impl LoadedSalt {
    /// A salt that is on disk and will be read back by every other process.
    /// `exposed` is what the loader observed about who can read that file, which
    /// every caller has to answer rather than inherit — see
    /// [`restrict_to_owner_only`].
    fn persisted(bytes: Vec<u8>, exposed: Option<String>) -> Self {
        Self {
            bytes,
            unpersisted: None,
            exposed,
        }
    }
}

fn load_or_create_machine_salt(dir: &Path) -> Result<LoadedSalt> {
    let path = dir.join("hook-salt");
    // `true` means the file exists but is unusable (must be force-overwritten);
    // `false` means it is absent (first run — create atomically to avoid a race).
    let must_overwrite = match std::fs::read(&path) {
        Ok(bytes) if bytes.len() >= 16 => {
            // Valid: adopt it, but correct its permissions in case an external
            // actor (backup restore, older build) left it looser than 0600 —
            // and report what the file is *still* readable by if that correction
            // did not take (issue #141).
            let exposed = restrict_to_owner_only(&path);
            return Ok(LoadedSalt::persisted(bytes, exposed));
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
        let exposed = write_secret_file(&path, &salt)
            .with_context(|| format!("writing {}", path.display()))?;
        return Ok(LoadedSalt::persisted(salt, exposed));
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
fn publish_secret_atomically(dir: &Path, path: &Path, salt: &[u8]) -> Result<LoadedSalt> {
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
        // The target is a fresh inode: the temp was created `O_CREAT|O_EXCL`
        // at mode 0600 and `hard_link` carries that mode across, so there is no
        // pre-existing mode to have inherited and nothing to observe.
        Ok(()) => Ok(LoadedSalt::persisted(salt.to_vec(), None)),
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
                // The winner's file, not ours — so its mode is observed here for
                // the same reason the top-level read path observes it.
                Ok(bytes) if bytes.len() >= 16 => {
                    let exposed = restrict_to_owner_only(path);
                    Ok(LoadedSalt::persisted(bytes, exposed))
                }
                Ok(bytes) => {
                    let reason = format!(
                        "winner salt file {} is short/corrupt ({} bytes) after a lost publish race",
                        path.display(),
                        bytes.len()
                    );
                    eprintln!("honmoon hook: {reason} — using our own salt for this invocation");
                    Ok(LoadedSalt {
                        bytes: salt.to_vec(),
                        unpersisted: Some(reason),
                        exposed: None,
                    })
                }
                Err(e) => {
                    let reason = format!(
                        "unexpected error reading salt file {} after a lost publish race ({e})",
                        path.display()
                    );
                    eprintln!("honmoon hook: {reason} — using our own salt for this invocation");
                    Ok(LoadedSalt {
                        bytes: salt.to_vec(),
                        unpersisted: Some(reason),
                        exposed: None,
                    })
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
///
/// Returns what [`restrict_to_owner_only`] observed, because the truncate path
/// reuses an *existing* inode: a fresh secret written into a file some external
/// actor left group/world-readable is exposed the moment it lands, exactly as an
/// adopted one is.
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<Option<String>> {
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
    Ok(restrict_to_owner_only(path))
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

/// Restrict `path` to `0600`, then report whether it is *still* readable beyond
/// its owner: `Some(reason)` naming the mode observed, `None` for owner-only.
///
/// The mode read back after the attempt is the signal, not the call's result.
/// Both directions of that matter:
/// - A failed `chmod` is not evidence of exposure. A read-only mount refuses the
///   call on a file that is already `0600`, and recording a degradation there
///   would be a false alarm — the kind that teaches operators to ignore the one
///   channel built to be read (issues #131, #141).
/// - A successful `chmod` is not evidence of safety. It closes the window going
///   forward and says nothing about who could read the file before. `None`
///   therefore attests "owner-only when the loader looked", never "never
///   exposed".
///
/// A mode that cannot be read back at all is reported as `None` after a stderr
/// line, for the first reason: an unverifiable mode is not an observed exposure,
/// and the loader has just read the file's contents, so this is a narrow window.
#[cfg(unix)]
fn restrict_to_owner_only(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!(
            "honmoon hook: could not restrict permissions on {} ({e}) — checking whether the salt is group/world-readable",
            path.display()
        );
    }
    let mode = match std::fs::metadata(path) {
        Ok(meta) => meta.permissions().mode() & 0o777,
        Err(e) => {
            eprintln!(
                "honmoon hook: could not read back the permissions of {} ({e}) — exposure unverified",
                path.display()
            );
            return None;
        }
    };
    (mode & 0o077 != 0).then(|| {
        format!(
            "salt file {} is readable beyond its owner (mode {mode:04o}) and could not be restricted to 0600",
            path.display()
        )
    })
}

/// Non-Unix hosts have no mode bits to observe, matching the `#[cfg(unix)]`
/// open modes and `/dev/urandom` elsewhere in this file.
#[cfg(not(unix))]
fn restrict_to_owner_only(_path: &Path) -> Option<String> {
    None
}

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
        assert_eq!(
            first.bytes.len(),
            32,
            "a freshly generated salt is 32 bytes"
        );
        assert!(first.unpersisted.is_none(), "it reached disk");
        let second = load_or_create_machine_salt(tmp.path()).expect("second load");
        assert_eq!(
            first.bytes, second.bytes,
            "second call reuses the persisted salt"
        );
    }

    #[test]
    fn machine_salt_regenerates_short_or_corrupt_file() {
        let tmp = TempDir::new("corrupt");
        std::fs::write(tmp.path().join("hook-salt"), b"tooshort").expect("seed corrupt file");
        let salt = load_or_create_machine_salt(tmp.path()).expect("regenerate");
        assert!(
            salt.bytes.len() >= 16,
            "a short file is discarded and regenerated"
        );
        assert_ne!(salt.bytes, b"tooshort".to_vec(), "not the corrupt bytes");
        assert!(salt.unpersisted.is_none(), "the rewrite reached disk");
        // The regenerated salt is itself persisted and stable thereafter.
        assert_eq!(
            salt.bytes,
            load_or_create_machine_salt(tmp.path())
                .expect("reload")
                .bytes
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
            salt.bytes,
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
        assert!(
            salt.exposed.is_none(),
            "a correction that took is not an exposure — the mode read back is 0600"
        );
    }

    /// A salt file this process can read but **cannot** `chmod` — the host
    /// condition the exposure check exists for, and the one a plain temp file
    /// cannot reproduce: we own it, so `set_permissions` always succeeds and the
    /// mode is always corrected.
    ///
    /// - **macOS**: a file's owner may set the `uchg` (user-immutable) flag
    ///   without privileges, after which `chmod(2)` fails with `EPERM` and the
    ///   mode stays exactly as seeded. [`UnrestrictableSalt`] clears the flag on
    ///   drop, or the temp dir could not be removed.
    /// - **Linux**: procfs rejects `chmod` outright — for root too, so this is
    ///   safe under any uid and mutates nothing — which makes a symlink at the
    ///   salt path pointing into `/proc` genuinely unrestrictable.
    ///   `/proc/version` is world-readable (`0444`), `/proc/self/auxv`
    ///   owner-only (`0400`), and both are comfortably over the loader's 16-byte
    ///   floor.
    ///
    /// The caller says which mode class it needs and this verifies the host
    /// actually delivered it — readable, long enough, `chmod` genuinely refused,
    /// and the group/world bits as asked. Neither arm of the exposure check may
    /// pass because the condition in its name quietly failed to materialise.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn unrestrictable_salt(dir: &Path, exposed: bool) -> UnrestrictableSalt {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("hook-salt");
        let guard = seed_unrestrictable_salt(&path, exposed);

        let bytes = std::fs::read(&path).expect("the seeded salt must be readable");
        assert!(
            bytes.len() >= 16,
            "the seeded salt must clear the loader's 16-byte floor, or it takes the regenerate path (got {} bytes)",
            bytes.len()
        );
        assert!(
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).is_err(),
            "this host let us chmod {} — the test would then prove nothing about an unrestrictable salt",
            path.display()
        );
        let mode = std::fs::metadata(&path)
            .expect("stat the seeded salt")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode & 0o077 != 0,
            exposed,
            "seeded salt has mode {mode:04o}, which is not the group/world exposure this arm asked for"
        );
        guard
    }

    /// Clears the macOS immutable flag so the temp dir can be removed; a Linux
    /// symlink needs no teardown, so the guard is empty there.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct UnrestrictableSalt {
        #[cfg(target_os = "macos")]
        path: PathBuf,
    }

    #[cfg(target_os = "macos")]
    fn seed_unrestrictable_salt(path: &Path, exposed: bool) -> UnrestrictableSalt {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, [5u8; 32]).expect("seed salt bytes");
        let mode = if exposed { 0o644 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("seed salt mode");
        set_immutable(path, true);
        UnrestrictableSalt {
            path: path.to_path_buf(),
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for UnrestrictableSalt {
        fn drop(&mut self) {
            set_immutable(&self.path, false);
        }
    }

    #[cfg(target_os = "macos")]
    fn set_immutable(path: &Path, immutable: bool) {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path without NUL");
        let flags = if immutable { libc::UF_IMMUTABLE } else { 0 };
        // SAFETY: `c_path` is a NUL-terminated path that outlives the call, and
        // `chflags` only reads it.
        let rc = unsafe { libc::chflags(c_path.as_ptr(), flags) };
        assert_eq!(
            rc,
            0,
            "chflags({}, {flags:#x}): {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }

    #[cfg(target_os = "linux")]
    fn seed_unrestrictable_salt(path: &Path, exposed: bool) -> UnrestrictableSalt {
        let target = if exposed {
            "/proc/version"
        } else {
            "/proc/self/auxv"
        };
        std::os::unix::fs::symlink(target, path).expect("point the salt path at a procfs entry");
        UnrestrictableSalt {}
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_readable_salt_that_cannot_be_restricted_is_audited_as_degraded() {
        use std::os::unix::fs::PermissionsExt;

        // The defect in #141: the read path adopts a valid salt and re-tightens
        // it, but a `chmod` that cannot be applied only ever reached stderr — so
        // a salt any local user can read was reported as a healthy persisted
        // key, and with it they can mint the placeholder a guessed secret would
        // produce for a session and confirm it against a redacted transcript.
        let tmp = TempDir::new("exposed-salt");
        let _guard = unrestrictable_salt(tmp.path(), true);
        let path = tmp.path().join("hook-salt");

        let key = machine_key_in(tmp.path());
        assert_ne!(
            key.as_slice(),
            FALLBACK_MACHINE_KEY,
            "the file was valid, so this is the persisted key, not the fallback"
        );
        assert!(
            matches!(key.status.source, MachineKeySource::Persisted),
            "provenance stays truthful: exposure is the other axis, not a fourth key source"
        );
        let mode = std::fs::metadata(&path)
            .expect("stat salt file")
            .permissions()
            .mode()
            & 0o777;
        let exposure = key
            .status
            .exposure
            .as_deref()
            .expect("a salt still readable beyond its owner after the attempt is an exposure");
        assert!(
            exposure.contains(&format!("{mode:04o}")),
            "the reason names the mode observed, not the chmod that failed: {exposure}"
        );

        // And it has to reach the durable sink, which is the hook's only channel.
        let log = tmp.path().join("audit.jsonl");
        audit_machine_key_status(Some(&log), &key.status);
        let line = std::fs::read_to_string(&log).expect("the audit log was written");
        let event: honmoon_core::AuditEvent =
            serde_json::from_str(line.trim()).expect("one JSONL event per line");
        assert_eq!(event.decision, honmoon_core::Decision::Degraded);
        assert_eq!(
            event.rule.as_deref(),
            Some(HOOK_SALT_EXPOSED_RULE),
            "its own rule — not the fallback's, which describes a different loss"
        );
        let redaction = event.facts.redaction.expect("redaction facts");
        assert_eq!(
            redaction.key_source,
            honmoon_core::RedactionKeySource::Persisted,
            "the key genuinely is the persisted one; saying otherwise would be the enum lying"
        );
        assert!(
            redaction.reason.contains(&format!("{mode:04o}")),
            "the recorded reason carries the observed mode: {}",
            redaction.reason
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn an_owner_only_salt_whose_chmod_fails_is_not_a_degradation() {
        // Why the signal is the mode read back rather than the `chmod` result: a
        // read-only mount refuses the call on a file that is already `0600`.
        // Recording there would raise a degraded event about a
        // correctly-permissioned key, and false alarms are how an audit channel
        // stops being read — which would undo what #131 asked for.
        let tmp = TempDir::new("unrestrictable-owner-only");
        let _guard = unrestrictable_salt(tmp.path(), false);

        let key = machine_key_in(tmp.path());
        assert!(matches!(key.status.source, MachineKeySource::Persisted));
        assert!(
            key.status.exposure.is_none(),
            "the chmod failed, but the file is owner-only — there is nothing to report: {:?}",
            key.status.exposure
        );

        let log = tmp.path().join("audit.jsonl");
        audit_machine_key_status(Some(&log), &key.status);
        assert!(
            !log.exists(),
            "an owner-only salt leaves the log untouched — not even an empty file"
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
            adopted.bytes, winner,
            "loser adopts the winner's bytes, not its own"
        );
        assert!(
            adopted.unpersisted.is_none(),
            "the winner's bytes are on disk, so they are the persisted key"
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
            adopted.bytes, ours,
            "a short winner file forces fallback to our own salt"
        );
        // The bytes are random and secret, so they are unforgeable — but they are
        // nobody else's, and reporting them as the persisted key would be a lie in
        // the one field that exists to be trusted.
        assert!(
            adopted.unpersisted.is_some(),
            "an unpersisted salt must not be reported as the persisted one"
        );
    }

    #[test]
    fn an_unpersisted_salt_is_audited_as_degraded_but_not_as_forgeable() {
        // The loser-with-a-short-winner arm hands back a salt that never reached
        // disk. It is random, so unforgeability holds; it is this process's alone,
        // so byte-stability across turns (#20) and across transports (#98) does
        // not. Both facts have to survive into the record: labelling it
        // `persisted` would hide a real degradation, and labelling it `fallback`
        // would claim placeholders are forgeable when they are not.
        let tmp = TempDir::new("unpersisted");
        std::fs::write(tmp.path().join("hook-salt"), b"tooshort").expect("seed short file");
        // A short *existing* file takes the overwrite path, which does persist —
        // so drive the lost-race arm directly, as its sibling test does.
        let loaded =
            publish_secret_atomically(tmp.path(), &tmp.path().join("hook-salt"), &[3u8; 32])
                .expect("publish loses to a short winner");
        let key = MachineKey {
            bytes: loaded.bytes,
            status: MachineKeyStatus {
                source: match loaded.unpersisted {
                    Some(reason) => MachineKeySource::Unpersisted { reason },
                    None => panic!("this arm must report the salt as unpersisted"),
                },
                exposure: loaded.exposed,
            },
        };
        assert_ne!(
            key.as_slice(),
            FALLBACK_MACHINE_KEY,
            "it is a random secret, not the published constant"
        );

        let audit = honmoon_core::AuditLog::new(2);
        record_machine_key_status(&audit, honmoon_core::RedactionTransport::Hook, &key.status)
            .expect("an in-memory log has no sink to fail");
        let event = audit.recent(1).remove(0);
        assert_eq!(event.decision, honmoon_core::Decision::Degraded);
        assert_eq!(
            event.facts.redaction.expect("redaction facts").key_source,
            honmoon_core::RedactionKeySource::Unpersisted,
            "distinct from both persisted and fallback"
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
                std::thread::spawn(move || {
                    let loaded = load_or_create_machine_salt(&dir).expect("load salt");
                    assert!(
                        loaded.unpersisted.is_none(),
                        "the hard_link publish leaves every racer holding the persisted key"
                    );
                    loaded.bytes
                })
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

    /// A directory honmoon can never create a salt in: its parent is a regular
    /// file, so `create_dir_all` fails with `NotADirectory` — the ordinary
    /// unwritable-`HOME` condition, made deterministic.
    fn unusable_salt_dir(tmp: &TempDir) -> PathBuf {
        let blocker = tmp.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").expect("seed blocker file");
        blocker.join("honmoon")
    }

    #[test]
    fn fallback_key_agrees_across_processes_yet_audits_as_degraded() {
        // The trap this guards: on the fallback path two independently-failing
        // processes derive the *same* key, because it is one public constant. So
        // every cross-transport parity assertion passes — byte-identical
        // placeholders for one secret — with unforgeability entirely absent. The
        // audit record is the only thing that tells the two apart; without it a
        // later reader can mistake a green parity test for evidence of a
        // guarantee that is switched off (issue #131).
        let tmp = TempDir::new("fallback-audit");
        let unusable = unusable_salt_dir(&tmp);

        let first = machine_key_in(&unusable);
        let second = machine_key_in(&unusable);
        assert_eq!(
            first.bytes, second.bytes,
            "two independent failures agree on one key — parity holds"
        );
        assert_eq!(
            first.bytes,
            FALLBACK_MACHINE_KEY.to_vec(),
            "and the key they agree on is the published constant"
        );
        // Parity all the way to the placeholder, under the identical session.
        let payload = serde_json::json!({ "session_id": "s-1" });
        assert_eq!(
            session_salt(&payload, None, &first),
            session_salt(&payload, None, &second),
            "so the placeholders match too, with nothing private behind them"
        );

        let audit = honmoon_core::AuditLog::new(8);
        record_machine_key_status(
            &audit,
            honmoon_core::RedactionTransport::Hook,
            &first.status,
        )
        .expect("an in-memory log has no sink to fail");
        record_machine_key_status(
            &audit,
            honmoon_core::RedactionTransport::Hook,
            &second.status,
        )
        .expect("an in-memory log has no sink to fail");
        let events = audit.recent(8);
        assert_eq!(
            events.len(),
            2,
            "every degraded derivation is recorded, not just the first"
        );
        let event = &events[0];
        assert_eq!(
            event.decision,
            honmoon_core::Decision::Degraded,
            "the fallback is not an ordinary allowed request"
        );
        assert_eq!(event.rule.as_deref(), Some("hook-salt-fallback"));
        let redaction = event
            .facts
            .redaction
            .as_ref()
            .expect("a degraded event carries redaction facts");
        assert_eq!(
            redaction.key_source,
            honmoon_core::RedactionKeySource::Fallback
        );
        assert_eq!(redaction.transport, honmoon_core::RedactionTransport::Hook);
        assert!(
            !redaction.reason.is_empty(),
            "the loader's error is carried through so the cause is diagnosable"
        );

        // The working path records nothing, so presence in the log is the signal.
        let healthy = machine_key_in(tmp.path());
        assert!(matches!(healthy.status.source, MachineKeySource::Persisted));
        let audit = honmoon_core::AuditLog::new(8);
        record_machine_key_status(
            &audit,
            honmoon_core::RedactionTransport::Hook,
            &healthy.status,
        )
        .expect("nothing to record");
        assert!(
            audit.is_empty(),
            "a persisted key is not a degradation and must not be logged as one"
        );
    }

    #[test]
    fn a_refused_sink_is_reported_rather_than_swallowed() {
        // The degradation record is its own only durable trace: this process
        // keeps no queryable ring, and with no `RUST_LOG` the `tracing::warn!`
        // inside `AuditLog::record` never reaches a writer. So a sink that
        // refuses the record has to come back as an error, not a silent `()`.
        let tmp = TempDir::new("sink-refused");
        let unusable = unusable_salt_dir(&tmp);
        let blocked_log = tmp.path().join("not-a-dir").join("audit.jsonl");
        assert!(
            honmoon_core::AuditLog::with_file(1, &blocked_log).is_err(),
            "the log path must be unopenable for this test to mean anything"
        );
        // The hook swallows it after a stderr line — reporting a degradation
        // must not itself become one — so this asserts only that it does not
        // panic or propagate, leaving the process's exit-0 contract intact.
        audit_machine_key_status(Some(&blocked_log), &machine_key_in(&unusable).status);
    }

    #[test]
    fn the_gateway_transport_is_recorded_distinctly_from_the_hook() {
        // `record_machine_key_source` takes the transport as a parameter, and the
        // gateway's call site is inside `gateway()`, which binds listeners and
        // blocks — so no test reaches it. Pin the value the gateway passes here,
        // so at least a swapped or renamed transport fails a test rather than
        // silently attributing a gateway degradation to the hook.
        let tmp = TempDir::new("gateway-transport");
        let unusable = unusable_salt_dir(&tmp);
        let audit = honmoon_core::AuditLog::new(2);
        record_machine_key_status(
            &audit,
            honmoon_core::RedactionTransport::Gateway,
            &machine_key_in(&unusable).status,
        )
        .expect("an in-memory log has no sink to fail");
        let event = audit.recent(1).remove(0);
        assert_eq!(
            event.facts.redaction.expect("redaction facts").transport,
            honmoon_core::RedactionTransport::Gateway
        );
    }

    #[test]
    fn degraded_event_reaches_the_durable_jsonl_sink() {
        // `honmoon hook` is a fresh process per invocation with no queryable ring,
        // so the record only counts if it lands in the file the query API reads.
        let tmp = TempDir::new("fallback-sink");
        let unusable = unusable_salt_dir(&tmp);
        let log = tmp.path().join("audit.jsonl");

        audit_machine_key_status(Some(&log), &machine_key_in(&unusable).status);
        let line = std::fs::read_to_string(&log).expect("the audit log was written");
        let event: honmoon_core::AuditEvent =
            serde_json::from_str(line.trim()).expect("one JSONL event per line");
        assert_eq!(event.decision, honmoon_core::Decision::Degraded);
        assert_eq!(
            event.facts.redaction.expect("redaction facts").key_source,
            honmoon_core::RedactionKeySource::Fallback
        );

        // A healthy key writes nothing at all — not even an empty file.
        let quiet = tmp.path().join("quiet.jsonl");
        audit_machine_key_status(Some(&quiet), &machine_key_in(tmp.path()).status);
        assert!(!quiet.exists(), "the working path leaves the log untouched");
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

    #[cfg(unix)]
    #[test]
    fn pre_tool_use_denies_dangling_symlink() {
        // A benign-named symlink whose target does not exist yet: `canonicalize`
        // returns `NotFound`, but the link exists, so a `Write` through it would
        // create the hidden target. It must be denied, not treated as a new file
        // — `symlink_metadata` distinguishes it from a genuinely absent path.
        let tmp = TempDir::new("dangling");
        let link = tmp.path().join("config");
        std::os::unix::fs::symlink(tmp.path().join("id_rsa"), &link).expect("dangling symlink");
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": link.to_string_lossy() }
        });
        let verdict = handle_hook(&payload, b"salt");
        assert_eq!(
            verdict["hookSpecificOutput"]["permissionDecision"], "deny",
            "a dangling symlink must not be allowed as a new file: {verdict}"
        );
    }
}
