//! Structured audit log: every verdict the engine reaches, recorded.
//!
//! [`AuditLog`] is the single-node, in-process record of decisions. It keeps a
//! bounded in-memory ring (so the management API can render recent activity
//! cheaply) and optionally mirrors every event to a JSONL file (the durable
//! local audit log the `@honmoon/api` query layer reads).
//!
//! It is transport-agnostic on purpose — the data plane (`honmoon-proxy`) and
//! the management API (`honmoon-mgmt`) share one `Arc<AuditLog>`.
//!
//! The **ring** is per process; the **JSONL file** is not. `honmoon hook` runs
//! as its own short-lived process and appends its degradation events to the
//! same path (see [`Decision::Degraded`]), so one file can hold the output of
//! several `AuditLog`s. Ids are therefore process-local and repeat across
//! writers — readers order by `timestamp` (`@honmoon/api`'s `queryAudit` says
//! so) — and only what reached *this* process's ring is visible through
//! `/api/audit`.

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Facts, HttpFacts, K8sFacts, PiiFacts, SqlFacts, Verdict};

/// What an audit entry records: the disposition of a request, or — for
/// [`Decision::Degraded`] — a security property the engine is running without.
///
/// A `Pause` verdict produces a `Paused` event when the request is held, then a
/// second `Approved`/`Rejected` event (sharing the same `approval_id`) once a
/// human resolves it — so the log is append-only and the full lifecycle is visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Request was allowed through.
    Allowed,
    /// Request was blocked.
    Denied,
    /// Request was held pending human approval.
    Paused,
    /// A held request was approved by a human and allowed through.
    Approved,
    /// A held request was rejected by a human (or timed out) and blocked.
    Rejected,
    /// Not a request disposition: the engine is running with a security
    /// property it normally provides switched off, and said so here.
    ///
    /// Honmoon's degradations are deliberately fail-open — a hook that hard-fails
    /// breaks the agent it runs inside — which makes them invisible from the
    /// outside: the degraded path produces the same shape of output as the
    /// working one. This variant is how a fail-open path stops being silent, so
    /// `?decision=degraded` answers "was this transcript redacted under a real
    /// key?" from the log rather than from a stderr line nobody read. The
    /// accompanying `verdict` describes what happened to the traffic (`allow`:
    /// fail-open let it through), not the degradation itself, and [`FactsSummary`]
    /// carries the specifics — see [`RedactionFacts`].
    Degraded,
}

/// What the engine knows about the key behind placeholder minting, recorded on a
/// [`Decision::Degraded`] event.
///
/// Two independent things can be wrong with that key, and the event's `rule`
/// says which: `hook-salt-fallback` for a key that is not the persisted one
/// (`key_source` then names what was lost), or one of two exposure rules for a
/// key that *is* the persisted one but whose file was readable beyond its owner
/// — `hook-salt-exposed` when it still is after the loader tried to restrict it
/// (issue #141), `hook-salt-was-exposed` when the loader found it that way and
/// the restriction took (issue #143). The two are separate because the remedies
/// are: a file that is loose now can be tightened, while one that was is a key
/// that may already be copied. Both keep `key_source` at
/// [`RedactionKeySource::Persisted`] deliberately — exposure and provenance are
/// different axes, and the bytes really did come from `~/.honmoon/hook-salt`.
///
/// Placeholders are `HMAC(salt, secret)`, and the salt is derived from a machine
/// key the transports read from disk. When that key cannot be read or created the
/// transports fall back to a constant compiled into the binary and published in
/// this repository's source: redaction keeps working and placeholders stay
/// byte-stable, but anyone can mint the placeholder a guessed secret would produce
/// and check it against a redacted transcript, so unforgeability is not weakened —
/// it is gone (issue #131). Nothing about the redacted output distinguishes the
/// two paths, which is why the provenance is recorded here instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionFacts {
    /// Where the HMAC key came from.
    pub key_source: RedactionKeySource,
    /// Which transport derived it.
    pub transport: RedactionTransport,
    /// What the loader observed, in its own words: why the persisted key was
    /// unavailable, or the modes it saw on a salt file readable beyond its owner
    /// — the one it was left with under `hook-salt-exposed`, the one it was found
    /// with under `hook-salt-was-exposed`.
    pub reason: String,
}

/// Whether placeholder minting was keyed by a private secret.
///
/// A closed two-value domain, so it is an enum rather than a string, matching
/// every other wire-serialized domain in this crate ([`Verdict`],
/// [`Decision`], `PathResolution`): a typo then fails to compile here instead
/// of failing to match on the query side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactionKeySource {
    /// The random secret persisted at `~/.honmoon/hook-salt`.
    ///
    /// Says where the bytes came from, not who else can read them — that is the
    /// event's `rule`, which is `hook-salt-exposed` when the loader found the
    /// file readable beyond its owner and could not restrict it, and
    /// `hook-salt-was-exposed` when it found it that way and the restriction
    /// took. So this value does appear on a degraded event, and an event
    /// carrying it is about the file's permissions rather than the key's
    /// provenance.
    Persisted,
    /// A private random secret that never reached disk, so it is unforgeable
    /// but lives and dies with one process: placeholders stop being stable
    /// across turns and across transports (the property issue #20 exists for),
    /// and no other process can reproduce them.
    Unpersisted,
    /// The public constant compiled into the binary. Unforgeability is not
    /// weakened here but absent — see [`Decision::Degraded`].
    Fallback,
}

/// Which transport recorded a [`RedactionFacts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactionTransport {
    /// The `honmoon hook` subprocess, which derives per invocation.
    Hook,
    /// The gateway process — wire redaction and the management hook endpoint,
    /// which share one key read once at startup.
    Gateway,
}

/// A compact, serializable snapshot of the [`Facts`] a decision was made on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FactsSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<SqlFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s: Option<K8sFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii: Option<PiiFacts>,
    /// Set only on a [`Decision::Degraded`] event; never derived from [`Facts`],
    /// which describes a request rather than the engine's own posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionFacts>,
}

impl From<&Facts> for FactsSummary {
    fn from(f: &Facts) -> Self {
        Self {
            domain: f.domain.clone(),
            endpoint: f.endpoint.clone(),
            http: f.http.clone(),
            sql: f.sql.clone(),
            k8s: f.k8s.clone(),
            pii: f.pii.clone(),
            redaction: None,
        }
    }
}

/// One recorded decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic per-process event id.
    pub id: u64,
    /// RFC 3339 / ISO 8601 UTC timestamp.
    pub timestamp: String,
    pub decision: Decision,
    /// The policy verdict that drove this event (`pause` for both the hold and
    /// its later resolution).
    pub verdict: Verdict,
    /// Name of the rule that fired, or `None` for an egress-list decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub facts: FactsSummary,
    /// Links a `Paused` event to the later `Approved`/`Rejected` event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<u64>,
}

/// What the caller knows at record time; `id`/`timestamp` are assigned by the log.
#[derive(Debug, Clone)]
pub struct AuditDraft {
    pub decision: Decision,
    pub verdict: Verdict,
    pub rule: Option<String>,
    pub facts: FactsSummary,
    pub approval_id: Option<u64>,
}

struct Ring {
    events: VecDeque<AuditEvent>,
    next_id: u64,
}

/// A bounded in-memory audit log with an optional durable JSONL mirror.
pub struct AuditLog {
    ring: Mutex<Ring>,
    capacity: usize,
    /// Optional append-only JSONL sink (one event per line).
    sink: Option<Mutex<std::fs::File>>,
    sink_path: Option<PathBuf>,
}

impl AuditLog {
    /// An in-memory-only log holding up to `capacity` recent events.
    pub fn new(capacity: usize) -> Self {
        Self {
            ring: Mutex::new(Ring {
                events: VecDeque::with_capacity(capacity.min(1024)),
                next_id: 1,
            }),
            capacity,
            sink: None,
            sink_path: None,
        }
    }

    /// Like [`new`](Self::new), additionally appending every event to a JSONL
    /// file at `path` (created if absent, mode `0600` on Unix). Existing event
    /// ids in the file are not re-read; the in-memory ring starts empty.
    ///
    /// `path` is operator-supplied (`--audit-log` / `HONMOON_AUDIT_LOG`) and,
    /// since issue #137, opened by `honmoon hook` as well as by the gateway.
    /// [`open_sink`] documents exactly which hostile targets the open refuses
    /// and which it still accepts.
    pub fn with_file(capacity: usize, path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let file = open_sink(&path)?;
        let mut log = Self::new(capacity);
        log.sink = Some(Mutex::new(file));
        log.sink_path = Some(path);
        Ok(log)
    }

    /// Path of the JSONL mirror, if one is configured.
    pub fn sink_path(&self) -> Option<&PathBuf> {
        self.sink_path.as_ref()
    }

    /// Record a decision; returns the stored event (with its assigned id).
    ///
    /// A sink write failure is logged and swallowed: it must not break
    /// enforcement, and the event still sits in this process's ring, so the
    /// management API can serve it. A caller whose process has neither — no
    /// `tracing` subscriber at that level, and no later reader of its ring —
    /// wants [`record_durable`](Self::record_durable) instead.
    pub fn record(&self, draft: AuditDraft) -> AuditEvent {
        let (event, sink) = self.record_durable(draft);
        if let Err(e) = sink {
            // A sink write failure must not break enforcement — log and carry on.
            tracing::warn!(error = %e, "audit sink write failed");
        }
        event
    }

    /// [`record`](Self::record), additionally handing back whether the durable
    /// JSONL sink took the event (`Ok(())` when there is no sink configured).
    ///
    /// For a short-lived writer the distinction is the whole point: `honmoon
    /// hook` is a fresh process per invocation with no ring anyone will query
    /// and, under a plugin dispatcher, no `RUST_LOG`, so `EnvFilter` drops a
    /// `warn!` before it is written — a swallowed sink failure there would make
    /// a degradation record vanish with no trace at all, which is the one
    /// outcome the degradation record exists to prevent (issue #131).
    pub fn record_durable(&self, draft: AuditDraft) -> (AuditEvent, std::io::Result<()>) {
        // Assign the id and update the ring under the lock, then release it
        // *before* any file I/O. Holding the ring lock across a synchronous
        // sink write would stall the gateway hot path (and serialize all audit
        // operations) behind a slow disk.
        let event = {
            let mut ring = self.ring.lock().expect("audit ring poisoned");
            let id = ring.next_id;
            ring.next_id += 1;
            let event = AuditEvent {
                id,
                timestamp: now_rfc3339(),
                decision: draft.decision,
                verdict: draft.verdict,
                rule: draft.rule,
                facts: draft.facts,
                approval_id: draft.approval_id,
            };
            ring.events.push_back(event.clone());
            while ring.events.len() > self.capacity {
                ring.events.pop_front();
            }
            event
        };

        // The sink has its own lock (writes stay ordered) and no longer contends
        // with the ring.
        let written = match &self.sink {
            Some(sink) => append_jsonl(sink, &event),
            None => Ok(()),
        };

        (event, written)
    }

    /// The most recent events, newest first, capped at `limit`.
    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let ring = self.ring.lock().expect("audit ring poisoned");
        ring.events.iter().rev().take(limit).cloned().collect()
    }

    /// Total number of events currently held in memory.
    pub fn len(&self) -> usize {
        self.ring.lock().expect("audit ring poisoned").events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Open the JSONL sink at `path` for appending, creating it owner-only on Unix.
///
/// "Owner-only", not "exactly `0600`": the creation mode is filtered through the
/// process umask, so `0600` is the ceiling the operator's umask can only narrow
/// (`umask 0200` yields `0400`). Narrower is never a weaker guarantee, so the mode
/// is passed as-is rather than forced with a `chmod` — which would also override a
/// deliberately restrictive umask.
///
/// The path comes from an operator flag, but the *directory* it sits in may not be
/// one only the honmoon user can write, and since issue #137 a second, short-lived
/// process (`honmoon hook`, spawned per agent invocation) opens the same path.
///
/// **Refused here:**
/// - A **symlink as the final path component**, via `O_NOFOLLOW` (open fails
///   `ELOOP`). A symlink pre-planted by another local user can no longer redirect
///   the append onto a file the honmoon user happens to be able to write, and a
///   *dangling* one can no longer quietly become the place the records go.
/// - **Anything that is not a regular file** — a FIFO, socket, device or
///   directory. The type is read with `fstat` on the descriptor this function is
///   already holding, never with a `stat` of the path, so nothing can be swapped
///   in between the check and the open. The FIFO is the case that matters:
///   `O_NOFOLLOW` does not refuse one, and a *blocking* open of one inside
///   `honmoon hook` stalls a process the agent will time out — after which the
///   invocation proceeds redacted by nothing at all. `O_NONBLOCK` is what stops
///   that open from blocking (a FIFO with no reader fails `ENXIO` at once); it
///   stays set on the descriptor afterwards, which is inert. POSIX specifies that
///   for a regular file "the `O_NONBLOCK` flag shall have no effect", and Linux
///   `write(2)` scopes its `EAGAIN` to a file *other than a socket* — pipes, FIFOs
///   and devices — so the flag cannot reach a write here, a regular file being all
///   this function returns. (The one historical exception, Linux mandatory locking
///   under `mount -o mand`, was removed in 5.15. Were it to fire anyway,
///   `append_jsonl` hands the error back to `record_durable` rather than losing the
///   record.)
///
/// **Still accepted, deliberately:**
/// - A **symlinked parent directory**. `O_NOFOLLOW` constrains the final
///   component only; every directory above it is still resolved through symlinks,
///   so an actor who controls a directory *on* the configured path still chooses
///   where the log lands. `openat2(RESOLVE_NO_SYMLINKS)` would close it in one
///   call but is Linux-only; the portable form is a component-by-component
///   `openat` walk with `O_NOFOLLOW` at each step, which macOS does support and
///   which is simply not written yet — a larger change with its own test surface
///   than this open. Tracked in issue #160.
/// - The **mode of a file that already exists**. `mode` applies only when this
///   call creates the file, so a log left group- or world-readable by an earlier
///   honmoon (which created it at the umask default) or by the operator keeps
///   that mode. Unlike the hook salt, which `restrict_to_owner_only` re-tightens
///   on every read (`honmoon-cli/src/hook.rs`), this path is chosen by the operator
///   and may be collected by a log shipper that was granted group read
///   deliberately; silently re-tightening it every time the gateway or a hook
///   process opens it would break that collection with no signal. Reporting it
///   instead needs a degradation event of its own — issue #161.
/// - **A final inode the attacker chose by means other than a symlink.** The two
///   bullets above are what `O_NOFOLLOW` and the type check cover; this one is the
///   same list read from the other side, because enumerating refused *link types*
///   hides everything that is not a link. An actor who can write the directory can
///   pre-create the path as an ordinary `0666` file, or `link(2)` it onto a file of
///   their own: both are regular files owned by nobody this code checks, so the
///   `fstat` passes, the creation mode never applies, and every record lands
///   somewhere they read. The payload is what makes that matter — the gateway's
///   records name hosts, SQL tables and PII categories, and a hook's degradation
///   record carries the absolute `$HOME` path of the salt it could not use. Closing
///   it means refusing a sink this process does not solely own (`uid`/`nlink` off
///   the same `fstat`), which is the same decision as #161's: whether honmoon may
///   refuse or re-tighten an audit file it did not create. Both are tracked there.
fn open_sink(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts.open(path).map_err(|e| explain_refusal(path, e))?;

    // `File::metadata` is `fstat` on the descriptor above, not a fresh lookup of
    // `path`, so this is the type of the object actually opened.
    let file_type = file.metadata()?.file_type();
    if !file_type.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "audit log {} is {}, not a regular file",
                path.display(),
                describe_file_type(&file_type)
            ),
        ));
    }
    Ok(file)
}

/// Rewrite the one open error whose wording actively misleads, and pass every
/// other one through in the OS's own words.
///
/// `O_NOFOLLOW` reports a refused symlink as `ELOOP` — "Too many levels of symbolic
/// links" — which describes a link *cycle*. An operator whose audit path is one
/// ordinary symlink (a rotation `current -> audit-2026-09-12.jsonl`, say) reads that
/// and learns nothing about why honmoon refused it, on a flag whose failure aborts
/// gateway startup. A parent-directory loop reports the same errno, so the
/// replacement names both rather than asserting which one happened.
#[cfg(unix)]
fn explain_refusal(path: &Path, e: std::io::Error) -> std::io::Error {
    if e.raw_os_error() != Some(libc::ELOOP) {
        return e;
    }
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "audit log {} was refused with ELOOP: the audit sink is opened with O_NOFOLLOW, \
             so a symlink as the final path component is refused (a symlink loop in a \
             parent directory reports the same error)",
            path.display()
        ),
    )
}

/// Non-Unix hosts get no `O_NOFOLLOW`, so there is no `ELOOP` of ours to explain.
#[cfg(not(unix))]
fn explain_refusal(_path: &Path, e: std::io::Error) -> std::io::Error {
    e
}

/// Name what [`open_sink`] found at the audit path, so the operator is told which
/// kind of wrong target they configured rather than only that it was wrong.
///
/// The list is short because it names only what a write-mode open can actually
/// succeed on. A directory (`EISDIR`), a socket (`ENXIO` on Linux, `EOPNOTSUPP`
/// on macOS) and a symlink (`O_NOFOLLOW` → `ELOOP`) never reach here: the open
/// has already failed with its own errno, which is what the caller reports.
#[cfg(unix)]
fn describe_file_type(file_type: &std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    if file_type.is_fifo() {
        "a FIFO"
    } else if file_type.is_char_device() {
        "a character device"
    } else if file_type.is_block_device() {
        "a block device"
    } else {
        "not a regular file"
    }
}

/// Non-Unix hosts have no `FileTypeExt`, and [`open_sink`] has no `O_NOFOLLOW`
/// there either — the regular-file check is all of the hardening that applies,
/// so the message stays generic. Split by `cfg` rather than branched inside one
/// body, matching `random_bytes` in `honmoon-cli/src/hook.rs`.
#[cfg(not(unix))]
fn describe_file_type(_file_type: &std::fs::FileType) -> &'static str {
    "not a regular file"
}

fn append_jsonl(sink: &Mutex<std::fs::File>, event: &AuditEvent) -> std::io::Result<()> {
    // Terminator appended in-buffer, because the sink is no longer single-writer:
    // `honmoon hook` runs as its own short-lived process and appends its own
    // degradation events to the same path (issue #131). Writing the newline
    // separately guaranteed a second syscall, and `O_APPEND` positions each one
    // at EOF independently, so a concurrent appender could land between an event
    // and its terminator and fuse two objects onto a line the reader drops as
    // malformed. One buffer removes that gap for the ordinary case — it is not a
    // hard guarantee: `write_all` loops on a short write, and atomic append is a
    // local-filesystem property NFS does not provide. A reader that must not lose
    // a record should treat a malformed line as a signal, not as noise.
    let mut line = serde_json::to_string(event)?;
    line.push('\n');
    let mut file = sink.lock().expect("audit sink poisoned");
    file.write_all(line.as_bytes())?;
    file.flush()
}

/// Current UTC time as an RFC 3339 string (shared timestamp source for events
/// and pending-approval records).
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(decision: Decision) -> AuditDraft {
        AuditDraft {
            decision,
            verdict: Verdict::Deny,
            rule: Some("r".into()),
            facts: FactsSummary {
                domain: Some("evil.com".into()),
                ..Default::default()
            },
            approval_id: None,
        }
    }

    #[test]
    fn assigns_monotonic_ids_and_orders_newest_first() {
        let log = AuditLog::new(10);
        let a = log.record(draft(Decision::Denied));
        let b = log.record(draft(Decision::Allowed));
        assert_eq!(a.id, 1);
        assert_eq!(b.id, 2);

        let recent = log.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].id, 2, "newest first");
        assert_eq!(recent[1].id, 1);
    }

    #[test]
    fn ring_is_bounded_to_capacity() {
        let log = AuditLog::new(3);
        for _ in 0..10 {
            log.record(draft(Decision::Denied));
        }
        assert_eq!(log.len(), 3);
        let recent = log.recent(100);
        assert_eq!(recent.len(), 3);
        // The three newest ids survive (8, 9, 10).
        assert_eq!(recent[0].id, 10);
        assert_eq!(recent[2].id, 8);
    }

    #[test]
    fn concurrent_writers_never_fuse_two_events_onto_one_line() {
        // The sink gained a second writer process (`honmoon hook`), which is why
        // `append_jsonl` emits the terminator in the same buffer as the record.
        // Threads here stand in for those processes: distinct `AuditLog`s over
        // one path, as two processes would have. Every line must still parse —
        // a fused line is one the reader drops, and the record most likely to be
        // lost is the `degraded` one that exists to be seen.
        let dir = std::env::temp_dir().join(format!(
            "honmoon-audit-concurrent-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        const WRITERS: usize = 8;
        const PER_WRITER: usize = 40;
        let handles: Vec<_> = (0..WRITERS)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let log = AuditLog::with_file(4, &path).expect("open sink");
                    for _ in 0..PER_WRITER {
                        log.record(draft(Decision::Denied));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("writer panicked");
        }

        let contents = std::fs::read_to_string(&path).expect("read sink");
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), WRITERS * PER_WRITER, "no record was lost");
        for line in &lines {
            serde_json::from_str::<AuditEvent>(line)
                .unwrap_or_else(|e| panic!("line is not one whole event ({e}): {line}"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_durable_reports_a_healthy_sink_and_an_absent_one_as_success() {
        // The two success arms: a sink that takes the record, and no sink at all
        // (nothing was refused, so it is not a failure). The refusal arm needs a
        // sink that fails *after* a successful open, which is below.
        let dir = std::env::temp_dir().join(format!("honmoon-audit-nosink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = AuditLog::with_file(4, dir.join("audit.jsonl")).expect("open sink");
        let (_, written) = log.record_durable(draft(Decision::Denied));
        assert!(written.is_ok(), "a healthy sink takes the record");

        let memory_only = AuditLog::new(4);
        let (event, written) = memory_only.record_durable(draft(Decision::Degraded));
        assert!(written.is_ok(), "no sink is not a refusal");
        assert_eq!(event.decision, Decision::Degraded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `/dev/full` accepts an open and fails every write with `ENOSPC`, which is
    /// the one portable-enough way to get a sink that refuses *after* opening —
    /// the case `record_durable` exists for (issue #131). Linux-only; macOS has
    /// no equivalent, so the assertion runs in CI's Linux job.
    ///
    /// The sink is installed directly rather than through
    /// [`AuditLog::with_file`], because that constructor now refuses a character
    /// device along with every other non-regular target (issue #138). The refusal
    /// is asserted by `with_file_refuses_a_character_device`; what is under test
    /// *here* is unchanged — a write that fails after a successful open has to
    /// come back to the caller.
    #[cfg(target_os = "linux")]
    #[test]
    fn record_durable_hands_back_a_sink_that_refuses_the_write() {
        let dev_full = std::fs::OpenOptions::new()
            .append(true)
            .open("/dev/full")
            .expect("/dev/full opens for append");
        let mut log = AuditLog::new(4);
        log.sink = Some(Mutex::new(dev_full));
        let (event, written) = log.record_durable(draft(Decision::Degraded));
        assert!(
            written.is_err(),
            "a refused write must come back to the caller, not be swallowed"
        );
        assert_eq!(
            log.len(),
            1,
            "the ring still holds it — only the durable copy was lost"
        );
        assert_eq!(event.decision, Decision::Degraded);
    }

    #[test]
    fn a_degraded_event_round_trips_with_its_redaction_facts() {
        // The wire shape the dashboard and `@honmoon/api` read: `redaction` is
        // present only here, and absent — not null — on every other event.
        let log = AuditLog::new(4);
        let event = log.record(AuditDraft {
            decision: Decision::Degraded,
            verdict: Verdict::Allow,
            rule: Some("hook-salt-fallback".into()),
            facts: FactsSummary {
                redaction: Some(RedactionFacts {
                    key_source: RedactionKeySource::Fallback,
                    transport: RedactionTransport::Hook,
                    reason: "unwritable HOME".into(),
                }),
                ..Default::default()
            },
            approval_id: None,
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""decision":"degraded""#), "{json}");
        assert!(json.contains(r#""key_source":"fallback""#), "{json}");
        assert!(json.contains(r#""transport":"hook""#), "{json}");
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.facts.redaction, event.facts.redaction);

        // An ordinary decision carries no `redaction` key at all.
        let ordinary = serde_json::to_string(&log.record(draft(Decision::Denied))).unwrap();
        assert!(!ordinary.contains("redaction"), "{ordinary}");
    }

    /// A unique directory under the system temp dir, matching the ad-hoc style
    /// the sink tests above already use. Named after the caller so parallel
    /// tests in one process do not collide.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "honmoon-audit-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// The audit path is operator-supplied and may sit in a directory another
    /// local user can write. A symlink planted there must not redirect the
    /// append onto the file it names (CWE-59, issue #138).
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_symlinked_target() {
        let dir = scratch_dir("symlink");
        let victim = dir.join("victim.conf");
        std::fs::write(&victim, "original\n").expect("seed victim");
        let link = dir.join("audit.jsonl");
        std::os::unix::fs::symlink(&victim, &link).expect("plant symlink");

        let Err(err) = AuditLog::with_file(4, &link) else {
            panic!("a symlinked sink must be refused");
        };
        assert_eq!(
            std::fs::read_to_string(&victim).expect("victim still readable"),
            "original\n",
            "the refused open must not have appended through the link: {err}"
        );
        // Pin *why* it was refused. `is_err()` alone would also pass if the open
        // failed for an unrelated reason, which would not prove `O_NOFOLLOW` is
        // what is doing the work.
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("opened with O_NOFOLLOW"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A *dangling* symlink is the quieter half of the same defect: the open
    /// would create the file the link names, so every record lands somewhere the
    /// operator is not looking.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_dangling_symlink() {
        let dir = scratch_dir("dangling");
        let elsewhere = dir.join("elsewhere.jsonl");
        let link = dir.join("audit.jsonl");
        std::os::unix::fs::symlink(&elsewhere, &link).expect("plant dangling symlink");

        let Err(err) = AuditLog::with_file(4, &link) else {
            panic!("a dangling symlinked sink must be refused");
        };
        assert!(err.to_string().contains("opened with O_NOFOLLOW"), "{err}");
        assert!(
            !elsewhere.exists(),
            "the refused open must not have created the link's target"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The trap `O_NOFOLLOW` alone does not close: a FIFO is not a symlink, and
    /// opening one for append *blocks* until a reader arrives. Inside `honmoon
    /// hook` — a process the agent times out — that stall means the invocation
    /// goes through redacted by nothing at all (issue #138).
    ///
    /// The open runs on its own thread with a deadline, so a regression fails
    /// this test instead of hanging the suite until CI's job timeout.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_fifo_without_blocking_on_it() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = scratch_dir("fifo");
        let fifo = dir.join("audit.jsonl");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
            .expect("path has no interior NUL");
        // SAFETY: `c_path` is a valid NUL-terminated path for the duration of the
        // call, and `mkfifo` only creates a filesystem entry.
        let made = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(
            made,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        let (tx, rx) = mpsc::channel();
        let probe = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(AuditLog::with_file(4, &probe).err().map(|e| e.to_string()));
        });
        let outcome = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO audit sink must not block");
        assert!(
            outcome.is_some(),
            "a FIFO audit sink must be refused, not accepted"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The half of the FIFO refusal the test above cannot reach. With no reader,
    /// `O_NONBLOCK` makes `open` itself fail `ENXIO` before `fstat` ever runs — so
    /// that test proves the sink does not block, and proves nothing about the
    /// regular-file check. Attach a reader first and the open *succeeds*; only the
    /// `fstat` refuses it.
    ///
    /// That is the adversarial ordering, not a curiosity: `O_NONBLOCK` alone is
    /// defeated by anyone who can hold the FIFO open for reading, and this check is
    /// the backstop. Without this test a regression that dropped
    /// `!file_type.is_file()` would still pass the suite.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_fifo_that_already_has_a_reader() {
        use std::os::unix::fs::OpenOptionsExt;

        let dir = scratch_dir("fifo-reader");
        let fifo = dir.join("audit.jsonl");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
            .expect("path has no interior NUL");
        // SAFETY: `c_path` is a valid NUL-terminated path for the duration of the
        // call, and `mkfifo` only creates a filesystem entry.
        let made = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(
            made,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        // `O_RDONLY | O_NONBLOCK` on a FIFO returns at once instead of waiting for
        // a writer, so the reader is attached before the open under test runs.
        let _reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .expect("attach a reader to the FIFO");

        let Err(err) = AuditLog::with_file(4, &fifo) else {
            panic!("a FIFO with a reader opens successfully and must be refused by the type check");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("a FIFO"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A character device is not a durable audit sink either — and unlike a FIFO
    /// or a socket it opens *successfully*, so this is the one refusal that can
    /// only come from the post-open `fstat`. `/dev/null` rather than `/dev/full`
    /// because it exists on every Unix; this is also the constructor half of
    /// `record_durable_hands_back_a_sink_that_refuses_the_write`, which installs
    /// its sink directly because of this refusal.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_character_device() {
        let Err(err) = AuditLog::with_file(4, "/dev/null") else {
            panic!("a character device is not a regular file");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("a character device"), "{err}");
    }

    /// The sink is created owner-only: the gateway's records name hosts, SQL
    /// tables and PII categories, and a hook's degradation record carries the
    /// absolute `$HOME` path of the salt it could not use.
    ///
    /// The assertion is `mode & 0o077 == 0`, not `mode == 0o600`, because the
    /// creation mode is filtered through the process umask — `0600` is a ceiling
    /// the operator's umask can only narrow (`umask 0200` yields `0400`, `umask
    /// 0777` yields `0000`). Owner-only is the property this test exists to hold;
    /// asserting the exact value would fail the suite on a machine whose umask is
    /// *stricter* than required, which is not a defect.
    #[cfg(unix)]
    #[test]
    fn a_created_sink_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("mode");
        let path = dir.join("audit.jsonl");
        let log = AuditLog::with_file(4, &path).expect("open sink");
        log.record(draft(Decision::Denied));

        let mode = std::fs::metadata(&path)
            .expect("stat sink")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "created sink is {mode:04o}, want no access beyond its owner"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The stated limit of the line above: the open mode applies on creation
    /// only, so a sink an operator (or an older honmoon, at the umask default)
    /// already left group-readable keeps that mode. Pinned so the decision is a
    /// tested behaviour rather than a claim in a doc comment — reporting it
    /// instead is issue #161.
    #[cfg(unix)]
    #[test]
    fn an_existing_sink_keeps_the_mode_it_had() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("existing-mode");
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, "").expect("seed sink");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen sink");

        let log = AuditLog::with_file(4, &path).expect("open sink");
        log.record(draft(Decision::Denied));

        let mode = std::fs::metadata(&path)
            .expect("stat sink")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o644,
            "an existing sink must keep its mode, not be silently re-tightened"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An ordinary regular-file sink still opens, appends, and reports its path
    /// exactly as before the open was hardened.
    #[test]
    fn a_regular_file_sink_still_opens_and_appends() {
        let dir = scratch_dir("regular");
        let path = dir.join("audit.jsonl");
        let log = AuditLog::with_file(4, &path).expect("a regular file is a valid sink");
        assert_eq!(log.sink_path(), Some(&path));
        log.record(draft(Decision::Allowed));

        let contents = std::fs::read_to_string(&path).expect("read sink");
        assert_eq!(contents.lines().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jsonl_sink_appends_one_line_per_event() {
        let dir = std::env::temp_dir().join(format!("honmoon-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        let log = AuditLog::with_file(10, &path).unwrap();
        log.record(draft(Decision::Denied));
        log.record(draft(Decision::Paused));

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line round-trips back to an AuditEvent.
        let first: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.id, 1);
        assert_eq!(first.decision, Decision::Denied);
        let _ = std::fs::remove_file(&path);
    }
}
